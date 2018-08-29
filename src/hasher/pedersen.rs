use byteorder::{ByteOrder, LittleEndian};
use merkle_light::hash::{Algorithm, Hashable};
use merkle_light::merkle;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField, PrimeFieldRepr};
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use std::fmt;
use std::hash::Hasher;

use crypto::pedersen;

#[derive(Copy, Clone)]
pub struct PedersenAlgorithm(Fr, [bool; 32 * 8]);

impl Default for PedersenAlgorithm {
    fn default() -> PedersenAlgorithm {
        PedersenAlgorithm::new()
    }
}

impl fmt::Debug for PedersenAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PedersenAlgorithm({:?})", self.0)
    }
}

impl Hashable<PedersenAlgorithm> for Fr {
    fn hash(&self, state: &mut PedersenAlgorithm) {
        let mut bytes = Vec::with_capacity(32);
        self.into_repr().write_le(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PedersenHash(pub Fr);

impl Default for PedersenHash {
    fn default() -> PedersenHash {
        PedersenHash::new()
    }
}

impl PedersenHash {
    fn new() -> PedersenHash {
        PedersenHash(Fr::from_repr(FrRepr::from(0)).expect("failed 0"))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        self.0.into_repr().write_le(&mut bytes).unwrap();

        bytes
    }
}

impl Ord for PedersenHash {
    #[inline(always)]
    fn cmp(&self, other: &PedersenHash) -> ::std::cmp::Ordering {
        (self.0).into_repr().cmp(&other.0.into_repr())
    }
}

impl PartialOrd for PedersenHash {
    #[inline(always)]
    fn partial_cmp(&self, other: &PedersenHash) -> Option<::std::cmp::Ordering> {
        Some((self.0).into_repr().cmp(&other.0.into_repr()))
    }
}

pub type MerkleTree = merkle::MerkleTree<PedersenHash, PedersenAlgorithm>;

impl PedersenAlgorithm {
    pub fn new() -> PedersenAlgorithm {
        PedersenAlgorithm(
            Fr::from_repr(FrRepr::default()).expect("failed default"),
            [false; 256],
        )
    }
}

impl AsRef<[u8]> for PedersenHash {
    fn as_ref(&self) -> &[u8] {
        // TODO: remove the requirment from the merkle lib for this method.
        // It was implemented wrong before, and is nearly unfixable.
        unimplemented!("not safe..");
    }
}

impl Hasher for PedersenAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        assert!(
            msg.len() <= 32,
            "can not process larger than 32byte messages"
        );

        for (i, byte) in msg.iter().enumerate() {
            for j in 0..8 {
                self.1[i * 8 + j] = byte >> j & 1u8 == 1u8
            }
        }

        let pt = pedersen_hash::<Bls12, _>(
            Personalization::NoteCommitment,
            self.1.iter().take(msg.len() * 8).cloned(),
            &pedersen::JJ_PARAMS,
        );
        self.0 = pt.into_xy().0
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl Algorithm<PedersenHash> for PedersenAlgorithm {
    #[inline]
    fn hash(&mut self) -> PedersenHash {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fr::from_repr(FrRepr::from(0)).expect("failed 0");
    }

    fn leaf(&mut self, leaf: PedersenHash) -> PedersenHash {
        leaf
    }

    fn node(&mut self, left: PedersenHash, right: PedersenHash, height: usize) -> PedersenHash {
        let lhs = left.0.into_repr().0;
        let rhs = right.0.into_repr().0;

        let len = Fr::NUM_BITS as usize;
        let mut bits = vec![false; 2 * len];

        let mut slhs = vec![0u8; 8];
        let mut srhs = vec![0u8; 8];
        for i in 0..4 {
            LittleEndian::write_u64(&mut slhs, lhs[i]);
            LittleEndian::write_u64(&mut srhs, rhs[i]);

            for k in 0..8 {
                for j in 0..8 {
                    let index = i * 64 + k * 8 + j;
                    // skip bit 255
                    if index == 255 {
                        continue;
                    }
                    bits[index] = (slhs[k] >> j) & 1u8 == 1u8;
                    bits[len + index] = (srhs[k] >> j) & 1u8 == 1u8;
                }
            }
        }

        pedersen_hash::<Bls12, _>(
            Personalization::MerkleTree(height),
            bits,
            &pedersen::JJ_PARAMS,
        ).into_xy()
        .0
        .into()
    }
}

impl From<Fr> for PedersenHash {
    #[inline(always)]
    fn from(val: Fr) -> Self {
        PedersenHash(val)
    }
}

impl From<PedersenHash> for Fr {
    #[inline(always)]
    fn from(val: PedersenHash) -> Self {
        val.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fr32::fr_into_bytes;
    use merkle_light::hash::Hashable;
    use pairing::BitIterator;

    #[test]
    fn test_path() {
        let values = ["hello", "world", "you", "two"];
        let t = MerkleTree::from_data(values.iter());

        let p = t.gen_proof(0); // create a proof for the first value = "hello"
        assert_eq!(*p.path(), vec![true, true]);
        assert_eq!(p.validate::<PedersenAlgorithm>(), true);
    }

    #[test]
    fn test_pedersen_hasher() {
        let values = ["hello", "world", "you", "two"];

        let t = MerkleTree::from_data(values.iter());

        assert_eq!(t.leafs(), 4);

        let mut a = PedersenAlgorithm::new();
        let leaves: Vec<PedersenHash> = values
            .iter()
            .map(|v| {
                v.hash(&mut a);
                let h = a.hash();
                a.reset();
                h
            }).collect();

        assert_eq!(t[0], leaves[0]);
        assert_eq!(t[1], leaves[1]);
        assert_eq!(t[2], leaves[2]);
        assert_eq!(t[3], leaves[3]);

        let i1 = a.node(leaves[0], leaves[1], 0);
        a.reset();
        let i2 = a.node(leaves[2], leaves[3], 0);
        a.reset();

        assert_eq!(t[4], i1);
        assert_eq!(t[5], i2);

        let root = a.node(i1, i2, 1);
        a.reset();

        assert_eq!(
            t[0].0,
            Fr::from_repr(FrRepr([
                5516429847681692214,
                1363403528947283679,
                5429691745410183571,
                7730413689037971367
            ])).unwrap()
        );

        let expected = Fr::from_repr(FrRepr([
            14963070332212552755,
            2414807501862983188,
            16116531553419129213,
            6357427774790868134,
        ])).unwrap();
        let actual = t[6].0;

        println!("expected bytes: {:?}", fr_into_bytes::<Bls12>(&expected));
        println!("  actual bytes: {:?}", fr_into_bytes::<Bls12>(&actual));

        assert_eq!(actual, expected);

        assert_eq!(t[6], root);
    }

    #[test]
    fn test_conversion() {
        let left = Fr::from_repr(FrRepr([1, 3, 1, 0])).unwrap();
        let right = Fr::from_repr(FrRepr([1, 1, 2, 0])).unwrap();

        let lhs = left.into_repr().0;
        let rhs = right.into_repr().0;

        let len = Fr::NUM_BITS as usize;
        let mut bits = vec![false; 2 * len];

        let mut slhs = vec![0u8; 8];
        let mut srhs = vec![0u8; 8];
        for i in 0..4 {
            LittleEndian::write_u64(&mut slhs, lhs[i]);
            println!("w {:?}", slhs);
            LittleEndian::write_u64(&mut srhs, rhs[i]);

            // iterate through each byte
            for k in 0..8 {
                // iterate through each bit
                for j in 0..8 {
                    let index = i * 64 + k * 8 + j;

                    // skip bit 255
                    if index == 255 {
                        continue;
                    }
                    bits[index] = (slhs[k] >> j) & 1u8 == 1u8;
                    bits[len + index] = (srhs[k] >> j) & 1u8 == 1u8;
                }
            }
        }
        print_bits(&bits[0..len].to_vec());

        // old

        let mut ol = BitIterator::new(left.into_repr()).collect::<Vec<bool>>();
        let mut or = BitIterator::new(right.into_repr()).collect::<Vec<bool>>();
        print_bits(&ol);
        ol.reverse();
        or.reverse();

        let old = ol
            .into_iter()
            .take(Fr::NUM_BITS as usize)
            .chain(or.into_iter().take(Fr::NUM_BITS as usize))
            .collect::<Vec<bool>>();
        print_bits(&old);

        assert_eq!(old, bits.to_vec());
    }

    fn print_bits(v: &[bool]) {
        let f = v
            .iter()
            .map(|a| if *a { 1 } else { 0 })
            .collect::<Vec<u8>>();
        println!("{:?}", f);
    }
}
