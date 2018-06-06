use bit_vec::BitVec;
use byteorder::{LittleEndian, WriteBytesExt};
use merkle_light::hash::Algorithm;
use merkle_light::merkle;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{BitIterator, PrimeField};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use std::hash::Hasher;
use std::iter::FromIterator;
use std::mem;

lazy_static! {
    static ref HASH_PARAMS: JubjubBls12 = JubjubBls12::new();
}

#[derive(Debug, Copy, Clone)]
pub struct PedersenAlgorithm(Fr);

impl Default for PedersenAlgorithm {
    fn default() -> PedersenAlgorithm {
        PedersenAlgorithm::new()
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
    fn new() -> PedersenAlgorithm {
        PedersenAlgorithm(Fr::from_repr(FrRepr::from(0)).expect("failed 0"))
    }
}

impl AsRef<[u8]> for PedersenHash {
    fn as_ref(&self) -> &[u8] {
        // TODO: figure out a safe way for this
        let r = self.0.into_repr();
        assert_eq!(r.as_ref().len(), 4);
        unsafe { mem::transmute::<&[u64], &[u8]>(r.as_ref()) }
    }
}

impl Hasher for PedersenAlgorithm {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        let bv = BitVec::from_bytes(msg);
        let pt = pedersen_hash::<Bls12, _>(Personalization::NoteCommitment, bv, &HASH_PARAMS);
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
        let mut lhs: Vec<bool> = BitIterator::new(left.0.into_repr()).collect();
        let mut rhs: Vec<bool> = BitIterator::new(right.0.into_repr()).collect();

        // Why??
        lhs.reverse();
        rhs.reverse();

        pedersen_hash::<Bls12, _>(
            Personalization::MerkleTree(height),
            lhs.into_iter()
                .take(Fr::NUM_BITS as usize)
                .chain(rhs.into_iter().take(Fr::NUM_BITS as usize)),
            &HASH_PARAMS,
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

pub fn merkle_tree_from_u64(data: Vec<u64>) -> MerkleTree {
    MerkleTree::from_iter(
        data.into_iter()
            .map(|x| pedersen_hash_u64::<Bls12>(x, &HASH_PARAMS).into()),
    )
}

pub fn pedersen_hash_u64<E: JubjubEngine>(value: u64, params: &E::Params) -> E::Fr {
    let mut contents = vec![];

    // Writing the value in little endian
    (&mut contents).write_u64::<LittleEndian>(value).unwrap();

    pedersen_hash::<E, _>(
        // TODO: what is the right type of personalization?
        Personalization::NoteCommitment,
        contents
            .into_iter()
            .flat_map(|byte| (0..8).map(move |i| ((byte >> i) & 1) == 1)),
        params,
    ).into_xy()
        .0
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_light::hash::Hashable;

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
        let leafs: Vec<PedersenHash> = values
            .iter()
            .map(|v| {
                v.hash(&mut a);
                let h = a.hash();
                a.reset();
                h
            })
            .collect();

        assert_eq!(t[0], leafs[0]);
        assert_eq!(t[1], leafs[1]);
        assert_eq!(t[2], leafs[2]);
        assert_eq!(t[3], leafs[3]);

        let i1 = a.node(leafs[0], leafs[1], 0);
        a.reset();
        let i2 = a.node(leafs[2], leafs[3], 0);
        a.reset();

        assert_eq!(t[4], i1);
        assert_eq!(t[5], i2);

        let root = a.node(i1, i2, 1);
        a.reset();

        assert_eq!(t[6], root);
    }
}
