#![allow(clippy::len_without_is_empty)]

use std::marker::PhantomData;

use anyhow::ensure;
use merkletree::hash::Algorithm;
use merkletree::merkle;
use merkletree::proof;
use merkletree::store::StoreConfig;
use paired::bls12_381::Fr;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::hasher::{Domain, Hasher};
use crate::util::{data_at_node, NODE_SIZE};

// Reexport here, so we don't depend on merkletree directly in other places.
use merkletree::merkle::FromIndexedParallelIterator;
pub use merkletree::store::Store;

type DiskStore<E> = merkletree::store::DiskStore<E>;
pub type MerkleTree<T, A> = merkle::MerkleTree<T, A, DiskStore<T>>;
pub type MerkleStore<T> = DiskStore<T>;

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

    pub fn into_options_with_leaf(self) -> (Option<Fr>, Vec<Option<(Fr, bool)>>) {
        let MerkleProof { leaf, path, .. } = self;

        (
            Some(leaf.into()),
            path.into_iter().map(|(a, b)| Some((a.into(), b))).collect(),
        )
    }

    pub fn as_pairs(&self) -> Vec<(Fr, bool)> {
        self.path
            .iter()
            .map(|v| (v.0.into(), v.1))
            .collect::<Vec<_>>()
    }

    fn verify(&self) -> bool {
        let mut a = H::Function::default();

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

    /// Validates the MerkleProof and that it corresponds to the supplied node.
    pub fn validate(&self, node: usize) -> bool {
        if path_index(&self.path) != node {
            return false;
        }

        self.verify()
    }

    /// Validates that the data hashes to the leaf of the merkle path.
    pub fn validate_data(&self, data: &[u8]) -> bool {
        if !self.verify() {
            return false;
        }

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

    pub fn verified_leaf(&self) -> IncludedNode<H> {
        IncludedNode::new(*self.leaf())
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
            out.extend(Domain::serialize(hash));
            out.push(*is_right as u8);
        }
        out.extend(Domain::serialize(self.leaf()));
        out.extend(Domain::serialize(self.root()));

        out
    }

    pub fn path(&self) -> &Vec<(H::Domain, bool)> {
        &self.path
    }

    /// proves_challenge returns true if this self.proof corresponds to challenge.
    /// This is useful for verifying that a supplied proof is actually relevant to a given challenge.
    pub fn proves_challenge(&self, challenge: usize) -> bool {
        let mut c = challenge;
        for (_, is_right) in self.path().iter() {
            if ((c & 1) == 1) ^ is_right {
                return false;
            };
            c >>= 1;
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncludedNode<H: Hasher> {
    value: H::Domain,
    _h: PhantomData<H>,
}

impl<H: Hasher> IncludedNode<H> {
    pub fn new(value: H::Domain) -> Self {
        IncludedNode {
            value,
            _h: PhantomData,
        }
    }

    pub fn into_fr(self) -> Fr {
        self.value.into()
    }
}

impl<H: Hasher> std::ops::Deref for IncludedNode<H> {
    type Target = H::Domain;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

fn path_index<T: Domain>(path: &[(T, bool)]) -> usize {
    path.iter().rev().fold(0, |acc, (_, is_right)| {
        (acc << 1) + if *is_right { 1 } else { 0 }
    })
}

/// Construct a new merkle tree.
pub fn create_merkle_tree<H: Hasher>(
    config: Option<StoreConfig>,
    size: usize,
    data: &[u8],
) -> Result<MerkleTree<H::Domain, H::Function>> {
    ensure!(
        data.len() == (NODE_SIZE * size) as usize,
        Error::InvalidMerkleTreeArgs(data.len(), NODE_SIZE, size)
    );

    let f = |i| {
        // TODO Replace `expect()` with `context()` (problem is the parallel iterator)
        let d = data_at_node(&data, i).expect("data_at_node math failed");
        // TODO/FIXME: This can panic. FOR NOW, let's leave this since we're experimenting with
        // optimization paths. However, we need to ensure that bad input will not lead to a panic
        // that isn't caught by the FPS API.
        // Unfortunately, it's not clear how to perform this error-handling in the parallel
        // iterator case.
        H::Domain::try_from_bytes(d).expect("failed to convert node data to domain element")
    };

    match config {
        Some(x) => MerkleTree::from_par_iter_with_config((0..size).into_par_iter().map(f), x),
        None => MerkleTree::from_par_iter((0..size).into_par_iter().map(f)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand;
    use std::io::Write;

    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};

    fn merklepath<H: Hasher>() {
        let g = BucketGraph::<H>::new(10, BASE_DEGREE, 0, new_seed()).unwrap();
        let mut rng = rand::thread_rng();
        let node_size = 32;
        let mut data = Vec::new();
        for _ in 0..10 {
            let elt: H::Domain = H::Domain::random(&mut rng);
            let bytes = H::Domain::into_bytes(&elt);
            data.write(&bytes).unwrap();
        }

        let tree = g.merkle_tree(data.as_slice()).unwrap();
        for i in 0..10 {
            let proof = tree.gen_proof(i).unwrap();

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
