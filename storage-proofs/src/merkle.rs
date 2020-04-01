#![allow(clippy::len_without_is_empty)]

use std::marker::PhantomData;
use std::path::PathBuf;

use anyhow::{ensure, Result};
use generic_array::typenum::{self, U0};
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

use generic_array::typenum::{UInt, UTerm, Unsigned, B1};
use generic_array::ArrayLength;

use crate::hasher::types::PoseidonArity;
use std::ops::Add;

// FIXME: Move from filecoin-proofs/src/constants to here?
pub const SECTOR_SIZE_2_KIB: u64 = 2_048;
pub const SECTOR_SIZE_8_MIB: u64 = 1 << 23;
pub const SECTOR_SIZE_512_MIB: u64 = 1 << 29;
pub const SECTOR_SIZE_32_GIB: u64 = 1 << 35;

pub const SECTOR_SIZE_4_KIB: u64 = 2 * SECTOR_SIZE_2_KIB;
pub const SECTOR_SIZE_16_MIB: u64 = 2 * SECTOR_SIZE_8_MIB;
pub const SECTOR_SIZE_1_GIB: u64 = 2 * SECTOR_SIZE_512_MIB;
pub const SECTOR_SIZE_64_GIB: u64 = 2 * SECTOR_SIZE_32_GIB;

// FIXME: Unsupported size, but used for quickly testing a top level
// tree consisting of 8x 4 KIB trees (each consisting of 2x 2 KIB trees)
pub const SECTOR_SIZE_32_KIB: u64 = 8 * SECTOR_SIZE_4_KIB;

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
pub type OctTopTree<H> = OctTopMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

pub type OctLCTree<H> = OctLCMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;
pub type OctLCSubTree<H> = OctLCSubMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;
pub type OctLCTopTree<H> = OctLCTopMerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

pub trait MerkleTreeTrait: Send + Sync {
    type Arity: 'static + PoseidonArity;
    type SubTreeArity: 'static + PoseidonArity;
    type TopTreeArity: 'static + PoseidonArity;
    type Hasher: Hasher;
    type Proof: MerkleProofTrait<
        Hasher = Self::Hasher,
        Arity = Self::Arity,
        SubTreeArity = Self::SubTreeArity,
        TopTreeArity = Self::TopTreeArity,
    >;

    fn display() -> String;
    fn root(&self) -> <Self::Hasher as Hasher>::Domain;
    fn gen_proof(&self, i: usize) -> Result<Self::Proof>;
}

pub trait MerkleProofTrait:
    Clone + Serialize + serde::de::DeserializeOwned + std::fmt::Debug + Sync + Send
{
    type Hasher: Hasher;
    type Arity: 'static + PoseidonArity;
    type SubTreeArity: 'static + PoseidonArity;
    type TopTreeArity: 'static + PoseidonArity;

    fn as_options(&self) -> Vec<(Vec<Option<Fr>>, Option<usize>)>;
    fn into_options_with_leaf(self) -> (Option<Fr>, Vec<(Vec<Option<Fr>>, Option<usize>)>);
    fn as_pairs(&self) -> Vec<(Vec<Fr>, usize)>;
    fn verify_sub_tree(&self, top_layer: bool) -> bool;
    fn verify(&self) -> bool;
    fn validate(&self, node: usize) -> bool;
    fn validate_data(&self, data: <Self::Hasher as Hasher>::Domain) -> bool;
    fn leaf(&self) -> <Self::Hasher as Hasher>::Domain;
    fn root(&self) -> &<Self::Hasher as Hasher>::Domain;
    fn verified_leaf(&self) -> IncludedNode<Self::Hasher>;
    fn len(&self) -> usize;
    fn serialize(&self) -> Vec<u8>;
    fn path(&self) -> &Vec<(Vec<<Self::Hasher as Hasher>::Domain>, usize)>;
    fn path_index(&self) -> usize;
    fn proves_challenge(&self, challenge: usize) -> bool;
}

impl<
        H: Hasher,
        S: Store<<H as Hasher>::Domain>,
        U: 'static + PoseidonArity,
        V: 'static + PoseidonArity,
        W: 'static + PoseidonArity,
    > MerkleTreeTrait for MerkleTreeWrapper<H, S, U, V, W>
{
    type Arity = U;
    type SubTreeArity = V;
    type TopTreeArity = W;
    type Hasher = H;
    type Proof = MerkleProof<Self::Hasher, Self::Arity, Self::SubTreeArity, Self::TopTreeArity>;

    fn display() -> String {
        format!("MerkleTree<{}>", U::to_usize())
    }

    fn root(&self) -> <Self::Hasher as Hasher>::Domain {
        self.inner.root()
    }

    fn gen_proof(&self, i: usize) -> Result<Self::Proof> {
        let proof = self.inner.gen_proof(i)?;
        Ok(MerkleProof::new_from_proof(&proof))
    }
}

macro_rules! forward_method {
    ($caller:expr, $name:ident) => {
        match $caller {
            ProofData::Single(proof) => proof.$name(),
            ProofData::Sub(proof) => proof.$name(),
            ProofData::Top(proof) => proof.$name(),
        }
    };
    ($caller:expr, $name:ident, $( $args:expr ),+) => {
        match $caller {
            ProofData::Single(proof) => proof.$name($($args),+),
            ProofData::Sub(proof) => proof.$name($($args),+),
            ProofData::Top(proof) => proof.$name($($args),+),
        }
    };
}

impl<
        H: Hasher,
        Arity: 'static + PoseidonArity,
        SubTreeArity: 'static + PoseidonArity,
        TopTreeArity: 'static + PoseidonArity,
    > MerkleProofTrait for MerkleProof<H, Arity, SubTreeArity, TopTreeArity>
{
    type Hasher = H;
    type Arity = Arity;
    type SubTreeArity = SubTreeArity;
    type TopTreeArity = TopTreeArity;

    fn as_options(&self) -> Vec<(Vec<Option<Fr>>, Option<usize>)> {
        forward_method!(self.data, as_options)
    }

    #[allow(clippy::type_complexity)]
    fn into_options_with_leaf(self) -> (Option<Fr>, Vec<(Vec<Option<Fr>>, Option<usize>)>) {
        forward_method!(self.data, into_options_with_leaf)
    }

    fn as_pairs(&self) -> Vec<(Vec<Fr>, usize)> {
        forward_method!(self.data, as_pairs)
    }

    fn verify(&self) -> bool {
        forward_method!(self.data, verify)
    }

    fn validate(&self, node: usize) -> bool {
        forward_method!(self.data, validate, node)
    }

    fn validate_data(&self, data: H::Domain) -> bool {
        forward_method!(self.data, validate_data, data)
    }

    fn leaf(&self) -> H::Domain {
        forward_method!(self.data, leaf)
    }

    fn root(&self) -> &H::Domain {
        forward_method!(self.data, root)
    }

    fn len(&self) -> usize {
        forward_method!(self.data, len)
    }

    fn serialize(&self) -> Vec<u8> {
        forward_method!(self.data, serialize)
    }

    fn path(&self) -> &Vec<(Vec<H::Domain>, usize)> {
        forward_method!(self.data, path)
    }

    fn path_index(&self) -> usize {
        forward_method!(self.data, path_index)
    }

    fn proves_challenge(&self, challenge: usize) -> bool {
        forward_method!(self.data, proves_challenge)
    }
}

pub struct MerkleTreeWrapper<
    H: Hasher,
    S: Store<<H as Hasher>::Domain>,
    U: PoseidonArity,
    V: PoseidonArity = typenum::U0,
    W: PoseidonArity = typenum::U0,
> {
    pub inner: merkle::MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function, S, U, V, W>,
    pub h: PhantomData<H>,
}

#[derive(Debug)]
pub enum OctTreeData<H: Hasher> {
    /// A BaseTree contains a single Store.
    Oct(OctTree<H>),

    /// A SubTree contains a list of BaseTrees.
    OctSub(OctSubTree<H>),

    /// A TopTree contains a list of SubTrees.
    OctTop(OctTopTree<H>),

    /// A BaseTree contains a single Store.
    OctLC(OctLCTree<H>),

    /// A SubTree contains a list of BaseTrees.
    OctLCSub(OctLCSubTree<H>),

    /// A TopTree contains a list of SubTrees.
    OctLCTop(OctLCTopTree<H>),
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

    pub fn octtoptree(&self) -> Option<&OctTopTree<H>> {
        match self {
            OctTreeData::OctTop(s) => Some(s),
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

    pub fn octlctoptree(&self) -> Option<&OctLCTopTree<H>> {
        match self {
            OctTreeData::OctLCTop(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PathElement<H: Hasher> {
    hashes: Vec<H::Domain>,
    index: usize,
}

/// Representation of a merkle proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof<
    H: Hasher,
    BaseArity: Unsigned,
    SubTreeArity: Unsigned = U0,
    TopTreeArity: Unsigned = U0,
> {
    data: ProofData<H, BaseArity, SubTreeArity, TopTreeArity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ProofData<H: Hasher, BaseArity: Unsigned, SubTreeArity: Unsigned, TopTreeArity: Unsigned> {
    Single(SingleProof<H, BaseArity>),
    Sub(SubProof<H, BaseArity, SubTreeArity>),
    Top(TopProof<H, BaseArity, SubTreeArity, TopTreeArity>),
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SingleProof<H: Hasher, Arity: Unsigned> {
    /// Root of the merkle tree.
    root: H::Domain,
    /// The original leaf data for this prof.
    leaf: H::Domain,
    /// The path from leaf to root.
    path: Vec<PathElement<H>>,
    #[serde(skip)]
    h: PhantomData<H>,
    #[serde(skip)]
    a: PhantomData<Arity>,
}

impl<H: Hasher, Arity: Unsigned> SingleProof<H, Arity> {
    pub fn new(root: H::Domain, leaf: H::Domain, path: Vec<PathElement<H>>) -> Self {
        SingleProof {
            root,
            leaf,
            path,
            h: Default::default(),
            a: Default::default(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct SubProof<H: Hasher, BaseArity: Unsigned, SubTreeArity: Unsigned> {
    base_proof: SingleProof<H, BaseArity>,
    sub_proof: SingleProof<H, SubTreeArity>,
    #[serde(skip)]
    h: PhantomData<H>,
    #[serde(skip)]
    b: PhantomData<SubTreeArity>,
}

impl<H: Hasher, BaseArity: Unsigned, SubTreeArity: Unsigned> SubProof<H, BaseArity, SubTreeArity> {
    pub fn new(
        base_proof: SingleProof<H, BaseArity>,
        sub_proof: SingleProof<H, SubTreeArity>,
    ) -> Self {
        Self {
            base_proof,
            sub_proof,
            h: Default::default(),
            b: Default::default(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct TopProof<H: Hasher, BaseArity: Unsigned, SubTreeArity: Unsigned, TopTreeArity: Unsigned> {
    base_proof: SingleProof<H, BaseArity>,
    sub_proof: SingleProof<H, SubTreeArity>,
    top_proof: SingleProof<H, TopTreeArity>,
    #[serde(skip)]
    h: PhantomData<H>,
    #[serde(skip)]
    c: PhantomData<TopTreeArity>,
}

impl<H: Hasher, BaseArity: Unsigned, SubTreeArity: Unsigned, TopTreeArity: Unsigned>
    TopProof<H, BaseArity, SubTreeArity, TopTreeArity>
{
    pub fn new(
        base_proof: SingleProof<H, BaseArity>,
        sub_proof: SingleProof<H, SubTreeArity>,
        top_proof: SingleProof<H, TopTreeArity>,
    ) -> Self {
        Self {
            base_proof,
            sub_proof,
            top_proof,
            h: Default::default(),
            c: Default::default(),
        }
    }
}

impl<
        H: Hasher,
        BaseArity: typenum::Unsigned,
        SubTreeArity: typenum::Unsigned,
        TopTreeArity: typenum::Unsigned,
    > MerkleProof<H, BaseArity, SubTreeArity, TopTreeArity>
{
    pub fn new_from_proof(p: &proof::Proof<H::Domain, BaseArity>) -> Result<Self> {
        ensure!(
            p.top_layer_nodes == TopTreeArity::to_usize(),
            "top arity mis-match"
        );
        ensure!(
            p.sub_layer_nodes == SubTreeArity::to_usize(),
            "sub arity mis-match"
        );

        let extract_path = |lemma, path| {
            lemma[1..lemma.len() - 1]
                .chunks(BaseArity::to_usize() - 1)
                .zip(path.iter())
                .map(|(hashes, index)| PathElement {
                    hashes: hashes.to_vec(),
                    index: *index,
                })
                .collect::<Vec<_>>()
        };

        // Converts a merkle_light proof to a SingleProof
        let proof_to_single = |proof| {
            let root = proof.root();
            let leaf = proof.item();
            let path = extract_path(proof.lemma(), proof.path);

            SingleProof::new(root, leaf, path)
        };

        if p.top_layer_nodes > 0 {
            ensure!(
                p.sub_tree_proof.is_some(),
                "Cannot generate top proof without a sub-proof"
            );
            let sub_p = p.sub_tree_proof.as_ref().unwrap();

            ensure!(
                sub_p.sub_tree_proof.is_some(),
                "Cannot generate top proof without a base-proof"
            );
            let base_p = sub_p.sub_tree_proof.as_ref().unwrap();

            // Generate TopProof
            let base_proof = proof_to_single(base_p);
            let sub_proof = proof_to_single(sub_p);
            let top_proof = proof_to_single(p);
            let proof = TopProof::new(base_proof, sub_proof, top_proof);

            Ok(MerkleProof {
                data: ProofData::Top(proof),
            })
        } else if p.sub_tree_layer_nodes > 0 {
            ensure!(
                p.sub_tree_proof.is_some(),
                "Cannot generate sub proof without a base-proof"
            );
            let base_p = p.sub_tree_proof.as_ref().unwrap();

            // Generate SubProof
            let base_proof = proof_to_single(base_p);
            let sub_proof = proof_to_single(p);
            let proof = SubProof::new(base_proof, sub_proof);

            Ok(MerkleProof {
                data: ProofData::Sub(proof),
            })
        } else {
            // Generate SingleProof
            let proof = proof_to_single(p);
            Ok(MerkleProof {
                data: ProofData::Single(proof),
            })
        }
    }
}

impl<H: Hasher, Arity: 'static + PoseidonArity> MerkleProofTrait for SingleProof<H, Arity> {
    type Hasher = H;
    type Arity = Arity;
    type SubTreeArity = typenum::U0;
    type TopTreeArity = typenum::U0;

    fn as_options(&self) -> Vec<(Vec<Option<Fr>>, Option<usize>)> {
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
    fn into_options_with_leaf(self) -> (Option<Fr>, Vec<(Vec<Option<Fr>>, Option<usize>)>) {
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

    fn as_pairs(&self) -> Vec<(Vec<Fr>, usize)> {
        self.path
            .iter()
            .map(|v| (v.0.iter().copied().map(Into::into).collect(), v.1))
            .collect::<Vec<_>>()
    }

    fn verify_sub_tree(&self, top_layer: bool) -> bool {
        assert!(self.sub_tree_proof.is_some());
        let sub_tree = self.sub_tree_proof.as_ref().unwrap();
        if !sub_tree.verify() {
            return false;
        }

        let mut a = H::Function::default();
        if top_layer {
            let expected_root = (0..self.path.len()).fold(sub_tree.root().clone(), |h, i| {
                a.reset();

                let index = self.path[i].1;
                let mut nodes = self.path[i].0.clone();
                nodes.insert(index, h);

                a.multi_node(&nodes, i)
            });

            self.root() == &expected_root
        } else {
            let expected_root = (0..sub_tree.path.len()).fold(sub_tree.leaf, |h, i| {
                a.reset();

                let index = sub_tree.path[i].1;
                let mut nodes = sub_tree.path[i].0.clone();
                nodes.insert(index, h);

                a.multi_node(&nodes, i)
            });

            sub_tree.root() == &expected_root
        }
    }

    fn verify(&self) -> bool {
        if self.sub_tree_proof.is_some() {
            return self.verify_sub_tree(self.top_layer_nodes > 0);
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

    fn validate(&self, node: usize) -> bool {
        if self.top_layer_nodes > 0 || self.sub_layer_nodes > 0 {
            assert!(self.sub_tree_proof.is_some());
            let sub_path_index = if node < self.base_layer_nodes {
                node % self.base_layer_nodes
            } else {
                ((node / self.base_layer_nodes) * self.base_layer_nodes)
                    + (node % self.base_layer_nodes)
            };

            if sub_path_index != node {
                return false;
            }
        } else if self.path_index() != node {
            return false;
        }

        self.verify()
    }

    fn validate_data(&self, data: H::Domain) -> bool {
        if !self.verify() {
            return false;
        }

        if self.top_layer_nodes > 0 || self.sub_layer_nodes > 0 {
            assert!(self.sub_tree_proof.is_some());
            return self.sub_tree_proof.as_ref().unwrap().validate_data(data);
        }

        self.leaf() == data
    }

    fn leaf(&self) -> H::Domain {
        self.leaf
    }

    fn root(&self) -> &H::Domain {
        &self.root
    }

    fn verified_leaf(&self) -> IncludedNode<H> {
        IncludedNode::new(self.leaf())
    }

    fn len(&self) -> usize {
        self.path.len() * (Arity::to_usize() - 1) + 2
    }

    fn serialize(&self) -> Vec<u8> {
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

    fn path(&self) -> &Vec<(Vec<H::Domain>, usize)> {
        &self.path
    }

    fn path_index(&self) -> usize {
        self.path
            .iter()
            .rev()
            .fold(0, |acc, (_, index)| (acc * Arity::to_usize()) + index)
    }

    fn proves_challenge(&self, challenge: usize) -> bool {
        if self.top_layer_nodes > 0 || self.sub_layer_nodes > 0 {
            let sub_path_index = if challenge < self.base_layer_nodes {
                challenge % self.base_layer_nodes
            } else {
                ((challenge / self.base_layer_nodes) * self.base_layer_nodes)
                    + (challenge % self.base_layer_nodes)
            };

            return sub_path_index == challenge;
        }

        self.path_index() == challenge
    }
}

impl<H: Hasher, BaseArity: 'static + PoseidonArity, SubTreeArity: 'static + PoseidonArity>
    MerkleProofTrait for SubProof<H, BaseArity, SubTreeArity>
{
    type Hasher = H;
    type Arity = BaseArity;
    type SubTreeArity = SubTreeArity;
    type TopTreeArity = typenum::U0;

    fn as_options(&self) -> Vec<(Vec<Option<Fr>>, Option<usize>)> {
        todo!()
    }

    #[allow(clippy::type_complexity)]
    fn into_options_with_leaf(self) -> (Option<Fr>, Vec<(Vec<Option<Fr>>, Option<usize>)>) {
        todo!()
    }

    fn as_pairs(&self) -> Vec<(Vec<Fr>, usize)> {
        todo!()
    }

    fn verify_sub_tree(&self, top_layer: bool) -> bool {
        todo!()
    }

    fn verify(&self) -> bool {
        todo!()
    }

    fn validate(&self, node: usize) -> bool {
        todo!()
    }

    fn validate_data(&self, data: H::Domain) -> bool {
        todo!()
    }

    fn leaf(&self) -> H::Domain {
        todo!()
    }

    fn root(&self) -> &H::Domain {
        todo!()
    }

    fn verified_leaf(&self) -> IncludedNode<H> {
        todo!()
    }

    fn len(&self) -> usize {
        todo!()
    }

    fn serialize(&self) -> Vec<u8> {
        todo!()
    }

    fn path(&self) -> &Vec<(Vec<H::Domain>, usize)> {
        todo!()
    }

    fn path_index(&self) -> usize {
        todo!()
    }

    fn proves_challenge(&self, challenge: usize) -> bool {
        todo!()
    }
}

impl<
        H: Hasher,
        BaseArity: 'static + PoseidonArity,
        SubTreeArity: 'static + PoseidonArity,
        TopTreeArity: 'static + PoseidonArity,
    > MerkleProofTrait for TopProof<H, BaseArity, SubTreeArity, TopTreeArity>
{
    type Hasher = H;
    type Arity = BaseArity;
    type SubTreeArity = SubTreeArity;
    type TopTreeArity = TopTreeArity;

    fn as_options(&self) -> Vec<(Vec<Option<Fr>>, Option<usize>)> {
        todo!()
    }

    #[allow(clippy::type_complexity)]
    fn into_options_with_leaf(self) -> (Option<Fr>, Vec<(Vec<Option<Fr>>, Option<usize>)>) {
        todo!()
    }

    fn as_pairs(&self) -> Vec<(Vec<Fr>, usize)> {
        todo!()
    }

    fn verify_sub_tree(&self, top_layer: bool) -> bool {
        todo!()
    }

    fn verify(&self) -> bool {
        todo!()
    }

    fn validate(&self, node: usize) -> bool {
        todo!()
    }

    fn validate_data(&self, data: H::Domain) -> bool {
        todo!()
    }

    fn leaf(&self) -> H::Domain {
        todo!()
    }

    fn root(&self) -> &H::Domain {
        todo!()
    }

    fn verified_leaf(&self) -> IncludedNode<H> {
        todo!()
    }

    fn len(&self) -> usize {
        todo!()
    }

    fn serialize(&self) -> Vec<u8> {
        todo!()
    }

    fn path(&self) -> &Vec<(Vec<H::Domain>, usize)> {
        todo!()
    }

    fn path_index(&self) -> usize {
        todo!()
    }

    fn proves_challenge(&self, challenge: usize) -> bool {
        todo!()
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
