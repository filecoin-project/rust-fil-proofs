#![allow(clippy::len_without_is_empty)]

use std::marker::PhantomData;

// Reexport here, so we don't depend on merkletree directly in other places.
use merkletree::hash::Algorithm;
use merkletree::merkle;
#[cfg(not(feature = "disk-trees"))]
use merkletree::merkle::MmapStore;
use merkletree::merkle::VecStore;
use merkletree::proof;
use paired::bls12_381::Fr;

use crate::hasher::{Domain, Hasher};

// `mmap`ed `MerkleTree` (replacing the previously `Vec`-backed
// `MerkleTree`, now encapsulated in `merkle::VecStore` and exposed
// as `VecMerkleTree`).
pub type DiskMmapStore<E> = merkle_light::merkle::DiskMmapStore<E>;
pub type VecMerkleTree<T, A> = merkle::MerkleTree<T, A, VecStore<T>>;
#[cfg(feature = "disk-trees")]
pub type MerkleTree<T, A> = merkle::MerkleTree<T, A, DiskMmapStore<T>>;
#[cfg(not(feature = "disk-trees"))]
pub type MerkleTree<T, A> = merkle::MerkleTree<T, A, MmapStore<T>>;

/// Representation of a merkle proof.
/// Each element in the `path` vector consists of a tuple `(hash, is_right)`, with `hash` being the the hash of the node at the current level and `is_right` a boolean indicating if the path is taking the right path.
/// The first element is the hash of leaf itself, and the last is the root hash.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof<H: Hasher> {
    pub root: H::Domain,
    path: Vec<(H::Domain, bool)>,
    leaf: H::Domain,

    #[serde(skip)]
    _h: PhantomData<H>,
}

pub fn make_proof_for_test<H: Hasher>(
    root: H::Domain,
    leaf: H::Domain,
    path: Vec<(H::Domain, bool)>,
) -> MerkleProof<H> {
    MerkleProof {
        path,
        root,
        leaf,
        _h: PhantomData,
    }
}

impl<H: Hasher> MerkleProof<H> {
    pub fn new(n: usize) -> MerkleProof<H> {
        let mut m = MerkleProof::default();
        m.path = vec![(Default::default(), false); n];

        m
    }

    pub fn new_from_proof(p: &proof::Proof<H::Domain>) -> MerkleProof<H> {
        MerkleProof {
            path: p
                .lemma()
                .iter()
                .skip(1)
                .zip(p.path().iter())
                .map(|(hash, is_left)| (*hash, !is_left))
                .collect::<Vec<_>>(),
            root: p.root(),
            leaf: p.item(),
            _h: PhantomData,
        }
    }

    /// Convert the merkle path into the format expected by the circuits, which is a vector of options of the tuples.
    /// This does __not__ include the root and the leaf.
    pub fn as_options(&self) -> Vec<Option<(Fr, bool)>> {
        self.path
            .iter()
            .map(|v| Some((v.0.into(), v.1)))
            .collect::<Vec<_>>()
    }

    pub fn as_pairs(&self) -> Vec<(Fr, bool)> {
        self.path
            .iter()
            .map(|v| (v.0.into(), v.1))
            .collect::<Vec<_>>()
    }

    /// Validates the MerkleProof and that it corresponds to the supplied node.
    pub fn validate(&self, node: usize) -> bool {
        let mut a = H::Function::default();

        if path_index(&self.path) != node {
            return false;
        }

        self.root()
            == &(0..self.path.len()).fold(self.leaf, |h, i| {
                a.reset();
                let is_right = self.path[i].1;

                let (left, right) = if is_right {
                    (self.path[i].0, h)
                } else {
                    (h, self.path[i].0)
                };

                a.node(left, right, i)
            })
    }

    /// Validates that the data hashes to the leaf of the merkle path.
    pub fn validate_data(&self, data: &[u8]) -> bool {
        self.leaf().into_bytes() == data
    }

    /// Returns the hash of leaf that this MerkleProof represents.
    pub fn leaf(&self) -> &H::Domain {
        &self.leaf
    }

    /// Returns the root hash
    pub fn root(&self) -> &H::Domain {
        &self.root
    }

    /// Returns the length of the proof. That is all path elements plus 1 for the
    /// leaf and 1 for the root.
    pub fn len(&self) -> usize {
        self.path.len() + 2
    }

    /// Serialize into bytes.
    /// TODO: probably improve
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        for (hash, is_right) in &self.path {
            out.extend(hash.serialize());
            out.push(*is_right as u8);
        }
        out.extend(self.leaf().serialize());
        out.extend(self.root().serialize());

        out
    }

    pub fn path(&self) -> &Vec<(H::Domain, bool)> {
        &self.path
    }
}

fn path_index<T: Domain>(path: &[(T, bool)]) -> usize {
    path.iter().rev().fold(0, |acc, (_, is_right)| {
        (acc << 1) + if *is_right { 1 } else { 0 }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{self, Rng};
    use std::io::Write;

    use crate::drgraph::new_seed;
    use crate::drgraph::{BucketGraph, Graph};
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};

    fn merklepath<H: Hasher>() {
        let g = BucketGraph::<H>::new(10, 5, 0, new_seed());
        let mut rng = rand::thread_rng();
        let node_size = 32;
        let mut data = Vec::new();
        for _ in 0..10 {
            let elt: H::Domain = rng.gen();
            let bytes = H::Domain::into_bytes(&elt);
            data.write(&bytes).unwrap();
        }

        let tree = g.merkle_tree(data.as_slice()).unwrap();
        for i in 0..10 {
            let proof = tree.gen_proof(i);

            assert!(proof.validate::<H::Function>());
            let len = proof.lemma().len();
            let mp = MerkleProof::<H>::new_from_proof(&proof);

            assert_eq!(mp.len(), len);

            assert!(mp.validate(i), "failed to validate valid merkle path");
            let data_slice = &data[i * node_size..(i + 1) * node_size].to_vec();
            assert!(
                mp.validate_data(data_slice),
                "failed to validate valid data"
            );
        }
    }

    #[test]
    fn merklepath_pedersen() {
        merklepath::<PedersenHasher>();
    }

    #[test]
    fn merklepath_sha256() {
        merklepath::<Sha256Hasher>();
    }

    #[test]
    fn merklepath_blake2s() {
        merklepath::<Blake2sHasher>();
    }
}
