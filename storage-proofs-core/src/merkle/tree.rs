#![allow(clippy::len_without_is_empty)]

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

use anyhow::Result;
use filecoin_hashers::{Hasher, PoseidonArity};
use generic_array::typenum::U0;
use merkletree::{
    hash::Hashable,
    merkle::{FromIndexedParallelIterator, MerkleTree},
    store::{ReplicaConfig, Store, StoreConfig},
};
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator};

use crate::merkle::{LCTree, MerkleProof, MerkleProofTrait};

/// Trait used to abstract over the way Merkle Trees are constructed and stored.
pub trait MerkleTreeTrait: Send + Sync + Debug {
    type Arity: 'static + PoseidonArity;
    type SubTreeArity: 'static + PoseidonArity;
    type TopTreeArity: 'static + PoseidonArity;
    type Hasher: 'static + Hasher;
    type Store: Store<<Self::Hasher as Hasher>::Domain>;
    type Proof: MerkleProofTrait<
        Hasher = Self::Hasher,
        Arity = Self::Arity,
        SubTreeArity = Self::SubTreeArity,
        TopTreeArity = Self::TopTreeArity,
    >;

    /// Print a unique name for this configuration.
    fn display() -> String;
    /// Returns the root hash of the tree.
    fn root(&self) -> <Self::Hasher as Hasher>::Domain;
    /// Creates a merkle proof of the node at the given index.
    fn gen_proof(&self, index: usize) -> Result<Self::Proof>;
    fn gen_cached_proof(&self, i: usize, rows_to_discard: Option<usize>) -> Result<Self::Proof>;
    fn row_count(&self) -> usize;
    fn leaves(&self) -> usize;
    fn from_merkle(
        tree: MerkleTree<
            <Self::Hasher as Hasher>::Domain,
            <Self::Hasher as Hasher>::Function,
            Self::Store,
            Self::Arity,
            Self::SubTreeArity,
            Self::TopTreeArity,
        >,
    ) -> Self;
}

pub struct MerkleTreeWrapper<
    H: Hasher,
    S: Store<<H as Hasher>::Domain>,
    U: PoseidonArity,
    V: PoseidonArity = U0,
    W: PoseidonArity = U0,
> {
    pub inner: MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function, S, U, V, W>,
    pub h: PhantomData<H>,
}

impl<
        H: 'static + Hasher,
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
    type Store = S;
    type Proof = MerkleProof<Self::Hasher, Self::Arity, Self::SubTreeArity, Self::TopTreeArity>;

    fn display() -> String {
        format!(
            "merkletree-{}-{}-{}-{}",
            H::name(),
            U::to_usize(),
            V::to_usize(),
            W::to_usize()
        )
    }

    fn root(&self) -> <Self::Hasher as Hasher>::Domain {
        self.inner.root()
    }

    fn gen_proof(&self, i: usize) -> Result<Self::Proof> {
        let proof = self.inner.gen_proof(i)?;

        debug_assert!(proof.validate::<H::Function>().expect("validate failed"));

        MerkleProof::try_from_proof(proof)
    }

    fn gen_cached_proof(&self, i: usize, rows_to_discard: Option<usize>) -> Result<Self::Proof> {
        if rows_to_discard.is_some() && rows_to_discard.expect("rows to discard failure") == 0 {
            return self.gen_proof(i);
        }

        let proof = self.inner.gen_cached_proof(i, rows_to_discard)?;

        debug_assert!(proof.validate::<H::Function>().expect("validate failed"));

        MerkleProof::try_from_proof(proof)
    }

    fn row_count(&self) -> usize {
        self.inner.row_count()
    }

    fn leaves(&self) -> usize {
        self.inner.leafs()
    }

    fn from_merkle(
        tree: MerkleTree<
            <Self::Hasher as Hasher>::Domain,
            <Self::Hasher as Hasher>::Function,
            Self::Store,
            Self::Arity,
            Self::SubTreeArity,
            Self::TopTreeArity,
        >,
    ) -> Self {
        tree.into()
    }
}

impl<
        H: Hasher,
        S: Store<<H as Hasher>::Domain>,
        U: PoseidonArity,
        V: PoseidonArity,
        W: PoseidonArity,
    > From<MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function, S, U, V, W>>
    for MerkleTreeWrapper<H, S, U, V, W>
{
    fn from(tree: MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function, S, U, V, W>) -> Self {
        Self {
            inner: tree,
            h: Default::default(),
        }
    }
}

impl<
        H: Hasher,
        S: Store<<H as Hasher>::Domain>,
        U: PoseidonArity,
        V: PoseidonArity,
        W: PoseidonArity,
    > MerkleTreeWrapper<H, S, U, V, W>
{
    pub fn new<I: IntoIterator<Item = H::Domain>>(data: I) -> Result<Self> {
        let tree = MerkleTree::new(data)?;
        Ok(tree.into())
    }

    pub fn new_with_config<I: IntoIterator<Item = H::Domain>>(
        data: I,
        config: StoreConfig,
    ) -> Result<Self> {
        let tree = MerkleTree::new_with_config(data, config)?;
        Ok(tree.into())
    }

    pub fn from_data_with_config<O: Hashable<H::Function>, I: IntoIterator<Item = O>>(
        data: I,
        config: StoreConfig,
    ) -> Result<Self> {
        let tree = MerkleTree::from_data_with_config(data, config)?;
        Ok(tree.into())
    }

    pub fn from_data_store(data: S, leafs: usize) -> Result<Self> {
        let tree = MerkleTree::from_data_store(data, leafs)?;
        Ok(tree.into())
    }

    pub fn from_byte_slice_with_config(data: &[u8], config: StoreConfig) -> Result<Self> {
        let tree = MerkleTree::from_byte_slice_with_config(data, config)?;
        Ok(tree.into())
    }

    pub fn from_tree_slice(data: &[u8], leafs: usize) -> Result<Self> {
        let tree = MerkleTree::from_tree_slice(data, leafs)?;
        Ok(tree.into())
    }

    pub fn from_tree_slice_with_config(
        data: &[u8],
        leafs: usize,
        config: StoreConfig,
    ) -> Result<Self> {
        let tree = MerkleTree::from_tree_slice_with_config(data, leafs, config)?;
        Ok(tree.into())
    }

    pub fn from_trees(trees: Vec<MerkleTreeWrapper<H, S, U, U0, U0>>) -> Result<Self> {
        let trees = trees.into_iter().map(|t| t.inner).collect();
        let tree = MerkleTree::from_trees(trees)?;
        Ok(tree.into())
    }

    pub fn from_sub_trees(trees: Vec<MerkleTreeWrapper<H, S, U, V, U0>>) -> Result<Self> {
        let trees = trees.into_iter().map(|t| t.inner).collect();
        let tree = MerkleTree::from_sub_trees(trees)?;
        Ok(tree.into())
    }

    pub fn from_sub_trees_as_trees(trees: Vec<MerkleTreeWrapper<H, S, U, U0, U0>>) -> Result<Self> {
        let trees = trees.into_iter().map(|t| t.inner).collect();
        let tree = MerkleTree::from_sub_trees_as_trees(trees)?;
        Ok(tree.into())
    }

    pub fn from_slices(
        tree_data: &[&[u8]],
        leafs: usize,
    ) -> Result<MerkleTreeWrapper<H, S, U, V, U0>> {
        let tree =
            MerkleTree::<<H as Hasher>::Domain, <H as Hasher>::Function, S, U, V, U0>::from_slices(
                tree_data, leafs,
            )?;
        Ok(tree.into())
    }

    pub fn from_slices_with_configs(
        tree_data: &[&[u8]],
        leafs: usize,
        configs: &[StoreConfig],
    ) -> Result<Self> {
        let tree = MerkleTree::from_slices_with_configs(tree_data, leafs, configs)?;
        Ok(tree.into())
    }

    pub fn from_stores(leafs: usize, stores: Vec<S>) -> Result<Self> {
        let tree = MerkleTree::from_stores(leafs, stores)?;
        Ok(tree.into())
    }

    pub fn from_store_configs(leafs: usize, configs: &[StoreConfig]) -> Result<Self> {
        let tree = MerkleTree::from_store_configs(leafs, configs)?;
        Ok(tree.into())
    }

    pub fn from_store_configs_and_replica(
        leafs: usize,
        configs: &[StoreConfig],
        replica_config: &ReplicaConfig,
    ) -> Result<LCTree<H, U, V, W>> {
        let tree = MerkleTree::from_store_configs_and_replica(leafs, configs, replica_config)?;
        Ok(tree.into())
    }

    pub fn from_sub_tree_store_configs(leafs: usize, configs: &[StoreConfig]) -> Result<Self> {
        let tree = MerkleTree::from_sub_tree_store_configs(leafs, configs)?;
        Ok(tree.into())
    }

    pub fn try_from_iter<I: IntoIterator<Item = Result<H::Domain>>>(into: I) -> Result<Self> {
        let tree = MerkleTree::try_from_iter(into)?;
        Ok(tree.into())
    }

    pub fn from_sub_tree_store_configs_and_replica(
        leafs: usize,
        configs: &[StoreConfig],
        replica_config: &ReplicaConfig,
    ) -> Result<LCTree<H, U, V, W>> {
        let tree =
            MerkleTree::from_sub_tree_store_configs_and_replica(leafs, configs, replica_config)?;
        Ok(tree.into())
    }

    pub fn try_from_iter_with_config<I: IntoIterator<Item = Result<H::Domain>>>(
        into: I,
        config: StoreConfig,
    ) -> Result<Self> {
        let tree = MerkleTree::try_from_iter_with_config(into, config)?;
        Ok(tree.into())
    }

    pub fn from_par_iter<I>(par_iter: I) -> Result<Self>
    where
        I: IntoParallelIterator<Item = H::Domain>,
        I::Iter: IndexedParallelIterator,
    {
        let tree = MerkleTree::from_par_iter(par_iter)?;
        Ok(tree.into())
    }

    pub fn from_par_iter_with_config<I>(par_iter: I, config: StoreConfig) -> Result<Self>
    where
        I: IntoParallelIterator<Item = H::Domain>,
        I::Iter: IndexedParallelIterator,
    {
        let tree = MerkleTree::from_par_iter_with_config(par_iter, config)?;
        Ok(tree.into())
    }
}

impl<
        H: Hasher,
        S: Store<<H as Hasher>::Domain>,
        BaseArity: PoseidonArity,
        SubTreeArity: PoseidonArity,
        TopTreeArity: PoseidonArity,
    > Debug for MerkleTreeWrapper<H, S, BaseArity, SubTreeArity, TopTreeArity>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleTreeWrapper")
            .field("inner", &self.inner)
            .field("Hasher", &H::name())
            .finish()
    }
}

impl<
        H: Hasher,
        S: Store<<H as Hasher>::Domain>,
        BaseArity: PoseidonArity,
        SubTreeArity: PoseidonArity,
        TopTreeArity: PoseidonArity,
    > Deref for MerkleTreeWrapper<H, S, BaseArity, SubTreeArity, TopTreeArity>
{
    type Target = MerkleTree<H::Domain, H::Function, S, BaseArity, SubTreeArity, TopTreeArity>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<
        H: Hasher,
        S: Store<<H as Hasher>::Domain>,
        BaseArity: PoseidonArity,
        SubTreeArity: PoseidonArity,
        TopTreeArity: PoseidonArity,
    > DerefMut for MerkleTreeWrapper<H, S, BaseArity, SubTreeArity, TopTreeArity>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
