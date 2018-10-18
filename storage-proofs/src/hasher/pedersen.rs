use std::hash::Hasher as StdHasher;

use bitvec::{self, BitVec};
use merkle_light::hash::{Algorithm as LightAlgorithm, Hashable};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{PrimeField, PrimeFieldRepr};
use rand::{Rand, Rng};
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

use super::{Domain, HashFunction, Hasher};
use crypto::{kdf, pedersen, sloth};
use error::Result;
use fr32::{bytes_into_fr, fr_into_bytes};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct PedersenHasher {}

impl Hasher for PedersenHasher {
    type Domain = PedersenDomain;
    type Function = PedersenFunction;

    fn kdf(data: &[u8], m: usize) -> Self::Domain {
        kdf::kdf::<Bls12>(data, m).into()
    }

    fn sloth_encode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        sloth::encode::<Bls12>(&key.0, &ciphertext.0, rounds).into()
    }

    fn sloth_decode(key: &Self::Domain, ciphertext: &Self::Domain, rounds: usize) -> Self::Domain {
        sloth::decode::<Bls12>(&key.0, &ciphertext.0, rounds).into()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PedersenFunction(Fr);

impl Default for PedersenFunction {
    fn default() -> PedersenFunction {
        PedersenFunction(Fr::from_repr(FrRepr::default()).expect("failed default"))
    }
}

impl Hashable<PedersenFunction> for Fr {
    fn hash(&self, state: &mut PedersenFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.into_repr().write_le(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

impl Hashable<PedersenFunction> for PedersenDomain {
    fn hash(&self, state: &mut PedersenFunction) {
        let mut bytes = Vec::with_capacity(32);
        self.0.into_repr().write_le(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PedersenDomain(pub Fr);

impl Default for PedersenDomain {
    fn default() -> PedersenDomain {
        PedersenDomain(Fr::from_repr(FrRepr::default()).expect("failed default"))
    }
}

impl Rand for PedersenDomain {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        PedersenDomain(rng.gen())
    }
}

impl Ord for PedersenDomain {
    #[inline(always)]
    fn cmp(&self, other: &PedersenDomain) -> ::std::cmp::Ordering {
        (self.0).into_repr().cmp(&other.0.into_repr())
    }
}

impl PartialOrd for PedersenDomain {
    #[inline(always)]
    fn partial_cmp(&self, other: &PedersenDomain) -> Option<::std::cmp::Ordering> {
        Some((self.0).into_repr().cmp(&other.0.into_repr()))
    }
}

impl AsRef<[u8]> for PedersenDomain {
    fn as_ref(&self) -> &[u8] {
        // TODO: remove the requirment from the merkle lib for this method.
        // It was implemented wrong before, and is nearly unfixable.
        unimplemented!("not safe..");
    }
}

impl Domain for PedersenDomain {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32);
        self.0.into_repr().write_le(&mut bytes).unwrap();
        bytes
    }

    fn into_bytes(&self) -> Vec<u8> {
        fr_into_bytes::<Bls12>(&self.0).to_vec()
    }

    fn try_from_bytes(raw: &[u8]) -> Result<Self> {
        bytes_into_fr::<Bls12>(raw).map(|v| v.into())
    }

    fn write_bytes(&self, dest: &mut [u8]) -> Result<()> {
        self.0.into_repr().write_le(dest)?;
        Ok(())
    }
}

impl StdHasher for PedersenFunction {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0 = pedersen::pedersen(msg);
    }

    #[inline]
    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

impl HashFunction<PedersenDomain> for PedersenFunction {
    fn hash(data: &[u8]) -> PedersenDomain {
        pedersen::pedersen_md_no_padding(data).into()
    }
}

impl LightAlgorithm<PedersenDomain> for PedersenFunction {
    #[inline]
    fn hash(&mut self) -> PedersenDomain {
        self.0.into()
    }

    #[inline]
    fn reset(&mut self) {
        self.0 = Fr::from_repr(FrRepr::from(0)).expect("failed 0");
    }

    fn leaf(&mut self, leaf: PedersenDomain) -> PedersenDomain {
        leaf
    }

    fn node(
        &mut self,
        left: PedersenDomain,
        right: PedersenDomain,
        height: usize,
    ) -> PedersenDomain {
        let lhs = BitVec::<bitvec::LittleEndian, u64>::from(&left.0.into_repr().0[..]);
        let rhs = BitVec::<bitvec::LittleEndian, u64>::from(&right.0.into_repr().0[..]);

        let bits = lhs
            .iter()
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.iter().take(Fr::NUM_BITS as usize));

        pedersen_hash::<Bls12, _>(
            Personalization::MerkleTree(height),
            bits,
            &pedersen::JJ_PARAMS,
        )
        .into_xy()
        .0
        .into()
    }
}

impl From<Fr> for PedersenDomain {
    #[inline]
    fn from(val: Fr) -> Self {
        PedersenDomain(val)
    }
}

impl From<PedersenDomain> for Fr {
    #[inline]
    fn from(val: PedersenDomain) -> Self {
        val.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use merkle_light::hash::Hashable;

    use merkle::MerkleTree;

    #[test]
    fn test_path() {
        let values = ["hello", "world", "you", "two"];
        let t = MerkleTree::<PedersenDomain, PedersenFunction>::from_data(values.iter());

        let p = t.gen_proof(0); // create a proof for the first value = "hello"
        assert_eq!(*p.path(), vec![true, true]);
        assert_eq!(p.validate::<PedersenFunction>(), true);
    }

    #[test]
    fn test_pedersen_hasher() {
        let values = ["hello", "world", "you", "two"];

        let t = MerkleTree::<PedersenDomain, PedersenFunction>::from_data(values.iter());

        assert_eq!(t.leafs(), 4);

        let mut a = PedersenFunction::default();
        let leaves: Vec<PedersenDomain> = values
            .iter()
            .map(|v| {
                v.hash(&mut a);
                let h = a.hash();
                a.reset();
                h
            })
            .collect();

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
            ]))
            .unwrap()
        );

        let expected = Fr::from_repr(FrRepr([
            14963070332212552755,
            2414807501862983188,
            16116531553419129213,
            6357427774790868134,
        ]))
        .unwrap();
        let actual = t[6].0;

        println!("expected bytes: {:?}", fr_into_bytes::<Bls12>(&expected));
        println!("  actual bytes: {:?}", fr_into_bytes::<Bls12>(&actual));

        assert_eq!(actual, expected);

        assert_eq!(t[6], root);
    }
}
