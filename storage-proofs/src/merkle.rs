#![allow(clippy::len_without_is_empty)]

use std::marker::PhantomData;
use std::path::PathBuf;

use anyhow::ensure;
use generic_array::typenum;
use log::trace;
use merkletree::hash::Algorithm;
use merkletree::merkle;
use merkletree::merkle::{
    get_merkle_tree_leafs, get_merkle_tree_len, is_merkle_tree_size_valid,
    FromIndexedParallelIterator,
};
use merkletree::proof;
use merkletree::store::{LevelCacheStore, StoreConfig};
use paired::bls12_381::Fr;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::error::*;
use crate::hasher::{Domain, Hasher};
use crate::util::{data_at_node, NODE_SIZE};

// FIXME: Move from filecoin-proofs/src/constants to here?
pub const SECTOR_SIZE_2_KIB: u64 = 2_048;
pub const SECTOR_SIZE_8_MIB: u64 = 1 << 23;
pub const SECTOR_SIZE_512_MIB: u64 = 1 << 29;
pub const SECTOR_SIZE_32_GIB: u64 = 1 << 35;

pub const SECTOR_SIZE_4_KIB: u64 = 2 * SECTOR_SIZE_2_KIB;
pub const SECTOR_SIZE_16_MIB: u64 = 2 * SECTOR_SIZE_8_MIB;
pub const SECTOR_SIZE_1_GIB: u64 = 2 * SECTOR_SIZE_512_MIB;
pub const SECTOR_SIZE_64_GIB: u64 = 2 * SECTOR_SIZE_32_GIB;

// Reexport here, so we don't depend on merkletree directly in other places.
pub use merkletree::store::{ExternalReader, Store};

pub type DiskStore<E> = merkletree::store::DiskStore<E>;

pub type MerkleTree<T, A, U> = merkle::MerkleTree<T, A, DiskStore<T>, U>;
pub type LCMerkleTree<T, A, U> = merkle::MerkleTree<T, A, LevelCacheStore<T, std::fs::File>, U>;

pub type BinaryMerkleTree<T, A> = MerkleTree<T, A, typenum::U2>;
pub type BinaryLCMerkleTree<T, A> = LCMerkleTree<T, A, typenum::U2>;

pub type QuadMerkleTree<T, A> = MerkleTree<T, A, typenum::U4>;
pub type QuadLCMerkleTree<T, A> = LCMerkleTree<T, A, typenum::U4>;

pub type OctMerkleTree<T, A> = merkle::MerkleTree<T, A, DiskStore<T>, typenum::U8>;
pub type OctSubMerkleTree<T, A> = merkle::MerkleTree<T, A, DiskStore<T>, typenum::U8, typenum::U2>;
pub type OctTopMerkleTree<T, A> =
    merkle::MerkleTree<T, A, DiskStore<T>, typenum::U8, typenum::U8, typenum::U2>;

pub type OctLCMerkleTree<T, A> =
    merkle::MerkleTree<T, A, LevelCacheStore<T, std::fs::File>, typenum::U8>;
pub type OctLCSubMerkleTree<T, A> =
    merkle::MerkleTree<T, A, LevelCacheStore<T, std::fs::File>, typenum::U8, typenum::U2>;
pub type OctLCTopMerkleTree<T, A> = merkle::MerkleTree<
    T,
    A,
    LevelCacheStore<T, std::fs::File>,
    typenum::U8,
    typenum::U8,
    typenum::U2,
>;

pub type MerkleStore<T> = DiskStore<T>;

pub type BinaryTree<H> = BinaryMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

pub type OctTree<H> = OctMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;
pub type OctSubTree<H> = OctSubMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

pub type OctLCTree<H> = OctLCMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;
pub type OctLCSubTree<H> = OctLCSubMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

#[derive(Debug)]
pub enum OctTreeData<H: Hasher> {
    /// A BaseTree contains a single Store.
    Oct(OctTree<H>),

    /// A SubTree contains a list of BaseTrees.
    OctSub(OctSubTree<H>),

    /// A BaseTree contains a single Store.
    OctLC(OctLCTree<H>),

    /// A SubTree contains a list of BaseTrees.
    OctLCSub(OctLCSubTree<H>),
}

impl<H: Hasher> OctTreeData<H> {
    pub fn octtree(&self) -> Option<&OctTree<H>> {
        match self {
            OctTreeData::Oct(s) => Some(s),
            _ => None,
        }
    }

    pub fn octsubtree(&self) -> Option<&OctSubTree<H>> {
        match self {
            OctTreeData::OctSub(s) => Some(s),
            _ => None,
        }
    }

    pub fn octlctree(&self) -> Option<&OctLCTree<H>> {
        match self {
            OctTreeData::OctLC(s) => Some(s),
            _ => None,
        }
    }

    pub fn octlcsubtree(&self) -> Option<&OctLCSubTree<H>> {
        match self {
            OctTreeData::OctLCSub(s) => Some(s),
            _ => None,
        }
    }
}

use generic_array::typenum::{UInt, UTerm, Unsigned, B1};
use generic_array::ArrayLength;

use crate::hasher::types::PoseidonArity;
use std::ops::Add;

pub trait MerkleTreeTrait: Send + Sync {
    type Arity: 'static + PoseidonArity;
    type Hasher: Hasher;
    type Proof: MerkleProofTrait<Arity = Self::Arity>;

    fn display() -> String;
}

pub trait MerkleProofTrait: Clone + Serialize + serde::de::DeserializeOwned {
    type Arity: 'static + PoseidonArity;
}

impl<H: Hasher, S: Store<<H as Hasher>::Domain>, U: 'static + PoseidonArity> MerkleTreeTrait
    for MerkleTreeWrapper<H, S, U>
{
    type Arity = U;
    type Hasher = H;
    type Proof = MerkleProof<Self::Hasher, U>;

    fn display() -> String {
        format!("MerkleTree<{}>", U::to_usize())
    }
}

impl<H: Hasher, U: 'static + PoseidonArity> MerkleProofTrait for MerkleProof<H, U> {
    type Arity = U;
}

pub struct MerkleTreeWrapper<H: Hasher, S: Store<<H as Hasher>::Domain>, U: PoseidonArity> {
    pub inner: merkle::MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function, S, U>,
    pub h: PhantomData<H>,
}

/// Representation of a merkle proof.
/// Each element in the 'path' vector consists of a tuple '(hash, index)', with 'hash' being the hash of the node at the current level and 'index' an index into the path (based on arity).
/// The first element is the hash of leaf itself, and the last is the root hash.
#[derive(Clone, Serialize, Deserialize)]
pub struct MerkleProof<H: Hasher, Arity: typenum::Unsigned> {
    #[serde(bound(
        serialize = "H::Domain: Serialize",
        deserialize = "H::Domain: Deserialize<'de>"
    ))]
    pub sub_tree_proof: Option<Box<MerkleProof<H, Arity>>>,
    sub_tree_leafs: usize,

    top_layer_nodes: usize,
    sub_layer_nodes: usize,

    pub root: H::Domain,
    path: Vec<(Vec<H::Domain>, usize)>,
    leaf: H::Domain,

    #[serde(skip)]
    _h: PhantomData<H>,
    #[serde(skip)]
    _a: PhantomData<Arity>,
}

impl<H: Hasher, Arity: typenum::Unsigned> std::fmt::Debug
    for MerkleProof<H, Arity>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerkleProof")
            .field("sub_tree_proof", &self.sub_tree_proof)
            .field("root", &self.root)
            .field("path", &self.path)
            .field("leaf", &self.leaf)
            .field("H", &H::name())
            .field("Arity", &Arity::to_usize())
            .finish()
    }
}

pub fn make_proof_for_test<H: Hasher, Arity: typenum::Unsigned>(
    root: H::Domain,
    leaf: H::Domain,
    path: Vec<(Vec<H::Domain>, usize)>,
) -> MerkleProof<H, Arity> {
    MerkleProof {
        sub_tree_proof: None,
        sub_tree_leafs: 0,
        top_layer_nodes: 0,
        sub_layer_nodes: 0,
        path,
        root,
        leaf,
        _h: PhantomData,
        _a: PhantomData,
    }
}

impl<H: Hasher, Arity: typenum::Unsigned> MerkleProof<H, Arity> {
    pub fn new(n: usize) -> MerkleProof<H, Arity> {
        MerkleProof {
            sub_tree_proof: None,
            sub_tree_leafs: 0,
            top_layer_nodes: 0,
            sub_layer_nodes: 0,
            root: Default::default(),
            path: vec![(Default::default(), 0); n],
            leaf: Default::default(),
            _h: PhantomData,
            _a: PhantomData,
        }
    }

    pub fn new_from_proof(
        p: &proof::Proof<H::Domain, Arity>,
    ) -> MerkleProof<H, Arity> {
        let lemma = p.lemma();

        MerkleProof {
            sub_tree_proof: None,
            sub_tree_leafs: 0,
            top_layer_nodes: 0,
            sub_layer_nodes: 0,
            path: lemma[1..lemma.len() - 1]
                .chunks(Arity::to_usize() - 1)
                .map(|chunk| chunk.to_vec())
                .zip(p.path().iter().copied())
                .collect::<Vec<_>>(),
            root: p.root(),
            leaf: p.item(),
            _h: PhantomData,
            _a: PhantomData,
        }
    }

    pub fn new_from_sub_proof<TopTreeArity: typenum::Unsigned, SubTreeArity: typenum::Unsigned>(
        p: &proof::Proof<H::Domain, Arity>,
        sub_tree_leafs: usize,
    ) -> MerkleProof<H, Arity> {
        let sub_tree_proof = if p.sub_tree_proof.is_some() {
            if TopTreeArity::to_usize() > 0 {
                Some(Box::new(Self::new_from_sub_proof::<
                    typenum::U0,
                    SubTreeArity,
                >(
                    p.sub_tree_proof.as_ref().unwrap(),
                    sub_tree_leafs,
                )))
            } else {
                Some(Box::new(Self::new_from_proof(
                    p.sub_tree_proof.as_ref().unwrap(),
                )))
            }
        } else {
            None
        };

        MerkleProof {
            sub_tree_proof,
            sub_tree_leafs,
            top_layer_nodes: TopTreeArity::to_usize(),
            sub_layer_nodes: SubTreeArity::to_usize(),
            path: {
                let lemma = p.lemma();
                lemma[1..lemma.len() - 1]
                    .chunks(Arity::to_usize() - 1)
                    .map(|chunk| chunk.to_vec())
                    .zip(p.path().iter().copied())
                    .collect::<Vec<_>>()
            },
            root: p.root(),
            leaf: p.item(),
            _h: PhantomData,
            _a: PhantomData,
        }
    }

    /// Convert the merkle path into the format expected by the circuits, which is a vector of options of the tuples.
    /// This does __not__ include the root and the leaf.
    pub fn as_options(&self) -> Vec<(Vec<Option<Fr>>, Option<usize>)> {
        self.path
            .iter()
            .map(|v| {
                (
                    v.0.iter().copied().map(Into::into).map(Some).collect(),
                    Some(v.1),
                )
            })
            .collect::<Vec<_>>()
    }

    #[allow(clippy::type_complexity)]
    pub fn into_options_with_leaf(self) -> (Option<Fr>, Vec<(Vec<Option<Fr>>, Option<usize>)>) {
        let MerkleProof { leaf, path, .. } = self;

        (
            Some(leaf.into()),
            path.into_iter()
                .map(|(a, b)| {
                    (
                        a.iter().copied().map(Into::into).map(Some).collect(),
                        Some(b),
                    )
                })
                .collect(),
        )
    }

    pub fn as_pairs(&self) -> Vec<(Vec<Fr>, usize)> {
        self.path
            .iter()
            .map(|v| (v.0.iter().copied().map(Into::into).collect(), v.1))
            .collect::<Vec<_>>()
    }

    fn verify_sub_tree(&self) -> bool {
        let sub_tree = self.sub_tree_proof.as_ref().unwrap();
        if !sub_tree.verify() {
            return false;
        }

        let mut a = H::Function::default();
        let expected_root = (0..sub_tree.path.len()).fold(sub_tree.leaf, |h, i| {
            a.reset();

            let index = sub_tree.path[i].1;
            let mut nodes = sub_tree.path[i].0.clone();
            nodes.insert(index, h);

            a.multi_node(&nodes, i)
        });

        sub_tree.root() == &expected_root
    }

    fn verify(&self) -> bool {
        if self.top_layer_nodes > 0 || self.sub_layer_nodes > 0 {
            assert!(self.sub_tree_proof.is_some());
            return self.verify_sub_tree();
        }

        let mut a = H::Function::default();
        let expected_root = (0..self.path.len()).fold(self.leaf, |h, i| {
            a.reset();

            let index = self.path[i].1;
            let mut nodes = self.path[i].0.clone();
            nodes.insert(index, h);

            a.multi_node(&nodes, i)
        });

        self.root() == &expected_root
    }

    /// Validates the MerkleProof and that it corresponds to the supplied node.
    pub fn validate(&self, node: usize) -> bool {
        if self.top_layer_nodes > 0 {
            assert!(self.sub_tree_proof.is_some());
            let sub_path_index = if node < self.sub_tree_leafs {
                node % self.sub_tree_leafs
            } else {
                (self.top_layer_nodes - 1) * self.sub_tree_leafs + (node % self.sub_tree_leafs)
            };

            return sub_path_index == node;
        }

        if self.sub_layer_nodes > 0 {
            assert!(self.sub_tree_proof.is_some());
            let sub_path_index = if node < self.sub_tree_leafs {
                node % self.sub_tree_leafs
            } else {
                (self.sub_layer_nodes - 1) * self.sub_tree_leafs + (node % self.sub_tree_leafs)
            };

            return sub_path_index == node;
        }

        if self.path_index() != node {
            return false;
        }

        self.verify()
    }

    /// Validates that the data hashes to the leaf of the merkle path.
    pub fn validate_data(&self, data: H::Domain) -> bool {
        if !self.verify() {
            return false;
        }

        if self.top_layer_nodes > 0 || self.sub_layer_nodes > 0 {
            assert!(self.sub_tree_proof.is_some());
            return self.sub_tree_proof.as_ref().unwrap().validate_data(data);
        }

        self.leaf() == data
    }

    /// Returns the hash of leaf that this MerkleProof represents.
    pub fn leaf(&self) -> H::Domain {
        self.leaf
    }

    /// Returns the root hash
    pub fn root(&self) -> &H::Domain {
        &self.root
    }

    pub fn verified_leaf(&self) -> IncludedNode<H> {
        IncludedNode::new(self.leaf())
    }

    /// Returns the length of the proof. That is all path elements plus 1 for the
    /// leaf and 1 for the root.
    pub fn len(&self) -> usize {
        self.path.len() * (Arity::to_usize() - 1) + 2
    }

    /// Serialize into bytes.
    /// TODO: probably improve
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();

        for (hashes, is_right) in &self.path {
            for hash in hashes {
                out.extend(Domain::serialize(hash));
            }
            out.push(*is_right as u8);
        }
        out.extend(Domain::serialize(&self.leaf()));
        out.extend(Domain::serialize(self.root()));

        out
    }

    pub fn path(&self) -> &Vec<(Vec<H::Domain>, usize)> {
        &self.path
    }

    pub fn sub_path_index(&self, arity: usize) -> usize {
        assert!(self.sub_tree_proof.is_some());
        self.sub_tree_proof
            .as_ref()
            .unwrap()
            .path
            .iter()
            .rev()
            .fold(0, |acc, (_, index)| (acc * arity) + index)
    }

    pub fn path_index(&self) -> usize {
        self.path.iter().rev().fold(0, |acc, (_, index)| {
            (acc * Arity::to_usize()) + index
        })
    }

    /// proves_challenge returns true if this self.proof corresponds to challenge.
    /// This is useful for verifying that a supplied proof is actually relevant to a given challenge.
    pub fn proves_challenge(&self, challenge: usize) -> bool {
        if self.top_layer_nodes > 0 {
            //assert!(self.sub_tree_proof.is_some());
            //return self.sub_path_index(self.top_layer_nodes) == challenge;
            let sub_path_index = if challenge < self.sub_tree_leafs {
                challenge % self.sub_tree_leafs
            } else {
                self.sub_tree_leafs + (challenge % self.sub_tree_leafs)
            };

            return sub_path_index == challenge;
        }

        if self.sub_layer_nodes > 0 {
            //assert!(self.sub_tree_proof.is_some());
            //return self.sub_path_index(self.sub_layer_nodes) == challenge;
            let sub_path_index = if challenge < self.sub_tree_leafs {
                challenge % self.sub_tree_leafs
            } else {
                self.sub_tree_leafs + (challenge % self.sub_tree_leafs)
            };

            return sub_path_index == challenge;
        }

        self.path_index() == challenge
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

pub fn split_config(config: Option<StoreConfig>, count: usize) -> Result<Vec<Option<StoreConfig>>> {
    match config {
        Some(c) => {
            let mut configs = Vec::with_capacity(count);
            for i in 0..count {
                configs.push(Some(StoreConfig::from_config(
                    &c,
                    format!("{}-{}", c.id, i),
                    None,
                )));
            }
            Ok(configs)
        }
        None => Ok(vec![None]),
    }
}

/// Construct a new merkle tree.
pub fn create_merkle_tree<H: Hasher, BaseTreeArity: typenum::Unsigned>(
    config: Option<StoreConfig>,
    size: usize,
    data: &[u8],
) -> Result<MerkleTree<H::Domain, H::Function, BaseTreeArity>> {
    ensure!(
        data.len() == (NODE_SIZE * size) as usize,
        Error::InvalidMerkleTreeArgs(data.len(), NODE_SIZE, size)
    );

    trace!("create_merkle_tree called with size {}", size);
    trace!(
        "is_merkle_tree_size_valid({}, arity {}) = {}",
        size,
        BaseTreeArity::to_usize(),
        is_merkle_tree_size_valid(size, BaseTreeArity::to_usize())
    );
    ensure!(
        is_merkle_tree_size_valid(size, BaseTreeArity::to_usize()),
        "Invalid merkle tree size given the arity"
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

/// Construct a new level cache merkle tree, given the specified
/// config and replica_path.
///
/// Note that while we don't need to pass both the data AND the
/// replica path (since the replica file will contain the same data),
/// we pass both since we have access from all callers and this avoids
/// reading that data from the replica_path here.
pub fn create_lcmerkle_tree<H: Hasher, BaseTreeArity: typenum::Unsigned>(
    config: StoreConfig,
    size: usize,
    data: &[u8],
    replica_path: &PathBuf,
) -> Result<LCMerkleTree<H::Domain, H::Function, BaseTreeArity>> {
    trace!("create_lcmerkle_tree called with size {}", size);
    trace!(
        "is_merkle_tree_size_valid({}, arity {}) = {}",
        size,
        BaseTreeArity::to_usize(),
        is_merkle_tree_size_valid(size, BaseTreeArity::to_usize())
    );
    ensure!(
        is_merkle_tree_size_valid(size, BaseTreeArity::to_usize()),
        "Invalid merkle tree size given the arity"
    );
    ensure!(
        data.len() == size * std::mem::size_of::<H::Domain>(),
        "Invalid data length for merkle tree"
    );

    let f = |i| {
        let d = data_at_node(&data, i)?;
        H::Domain::try_from_bytes(d)
    };

    let mut lc_tree: LCMerkleTree<H::Domain, H::Function, BaseTreeArity> =
        LCMerkleTree::<H::Domain, H::Function, BaseTreeArity>::try_from_iter_with_config(
            (0..size).map(f),
            config,
        )?;

    lc_tree.set_external_reader_path(replica_path)?;

    Ok(lc_tree)
}

/// Open an existing level cache merkle tree, given the specified
/// config and replica_path.
pub fn open_lcmerkle_tree<H: Hasher, BaseTreeArity: typenum::Unsigned>(
    config: StoreConfig,
    size: usize,
    replica_path: &PathBuf,
) -> Result<LCMerkleTree<H::Domain, H::Function, BaseTreeArity>> {
    trace!("open_lcmerkle_tree called with size {}", size);
    trace!(
        "is_merkle_tree_size_valid({}, arity {}) = {}",
        size,
        BaseTreeArity::to_usize(),
        is_merkle_tree_size_valid(size, BaseTreeArity::to_usize())
    );
    ensure!(
        is_merkle_tree_size_valid(size, BaseTreeArity::to_usize()),
        "Invalid merkle tree size given the arity"
    );

    let tree_size = get_merkle_tree_len(size, BaseTreeArity::to_usize())?;
    let tree_store: LevelCacheStore<H::Domain, _> = LevelCacheStore::new_from_disk_with_reader(
        tree_size,
        BaseTreeArity::to_usize(),
        &config,
        ExternalReader::new_from_path(replica_path)?,
    )?;

    ensure!(
        size == get_merkle_tree_leafs(tree_size, BaseTreeArity::to_usize()),
        "Inconsistent lcmerkle tree"
    );

    LCMerkleTree::from_data_store(tree_store, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand;
    use std::io::Write;

    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::hasher::{Blake2sHasher, PedersenHasher, PoseidonHasher, Sha256Hasher};

    fn merklepath<H: Hasher, BaseTreeArity: typenum::Unsigned>() {
        let leafs = 64;
        let g = BucketGraph::<H>::new(leafs, BASE_DEGREE, 0, new_seed()).unwrap();
        let mut rng = rand::thread_rng();
        let node_size = 32;
        let mut data = Vec::new();
        for _ in 0..leafs {
            let elt: H::Domain = H::Domain::random(&mut rng);
            let bytes = H::Domain::into_bytes(&elt);
            data.write(&bytes).unwrap();
        }

        let tree = g.merkle_tree(None, data.as_slice()).unwrap();
        for i in 0..leafs {
            let proof = tree.gen_proof(i).unwrap();

            assert!(proof.validate::<H::Function>().expect("failed to validate"));
            let len = proof.lemma().len();
            let mp = MerkleProof::<H, BaseTreeArity>::new_from_proof(&proof);

            assert_eq!(mp.len(), len, "invalid prof len");

            assert!(mp.validate(i), "failed to validate valid merkle path");
            let data_slice = &data[i * node_size..(i + 1) * node_size].to_vec();
            assert!(
                mp.validate_data(H::Domain::try_from_bytes(data_slice).unwrap()),
                "failed to validate valid data"
            );
        }
    }

    #[test]
    fn merklepath_pedersen_binary() {
        merklepath::<PedersenHasher, typenum::U2>();
    }

    #[test]
    fn merklepath_sha256_binary() {
        merklepath::<Sha256Hasher, typenum::U2>();
    }

    #[test]
    fn merklepath_blake2s_binary() {
        merklepath::<Blake2sHasher, typenum::U2>();
    }

    #[test]
    fn merklepath_poseidon_binary() {
        merklepath::<PoseidonHasher, typenum::U2>();
    }

    #[test]
    fn merklepath_poseidon_quad() {
        merklepath::<PoseidonHasher, typenum::U4>();
    }

    #[test]
    fn merklepath_pedersen_quad() {
        merklepath::<PedersenHasher, typenum::U4>();
    }

    #[test]
    fn merklepath_sha256_quad() {
        merklepath::<Sha256Hasher, typenum::U4>();
    }

    #[test]
    fn merklepath_blake2s_quad() {
        merklepath::<Blake2sHasher, typenum::U4>();
    }

    #[test]
    fn merklepath_poseidon_oct() {
        merklepath::<PoseidonHasher, typenum::U8>();
    }

    #[test]
    fn merklepath_pedersen_oct() {
        merklepath::<PedersenHasher, typenum::U8>();
    }
}
