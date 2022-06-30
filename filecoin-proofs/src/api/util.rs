use std::any::TypeId;
use std::mem::size_of;

use anyhow::{Context, Result};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use filecoin_hashers::{Domain, Hasher, PoseidonArity};
use halo2_proofs::pasta::{Fp, Fq};
use merkletree::{
    hash::Algorithm,
    merkle::{get_merkle_tree_leafs, get_merkle_tree_len, Element},
    store::{Store, StoreConfig},
};
use storage_proofs_core::merkle::{get_base_tree_count, MerkleTreeTrait};
use typenum::{U0, U2, U8, Unsigned};

use crate::types::{Commitment, SectorSize};

pub fn as_safe_commitment<D: Domain, T: AsRef<str>>(
    comm: &[u8; 32],
    commitment_name: T,
) -> Result<D> {
    let mut repr = <D::Field as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(comm);
    D::Field::from_repr_vartime(repr)
        .map(Into::into)
        .with_context(|| format!("Invalid commitment ({})", commitment_name.as_ref(),))
}

pub fn commitment_from_fr<F: PrimeField>(fr: F) -> Commitment {
    let mut commitment = [0; 32];
    commitment.copy_from_slice(fr.to_repr().as_ref());
    commitment
}

pub fn get_base_tree_size<Tree: MerkleTreeTrait>(sector_size: SectorSize) -> Result<usize> {
    let base_tree_leaves = u64::from(sector_size) as usize
        / size_of::<<Tree::Hasher as Hasher>::Domain>()
        / get_base_tree_count::<Tree>();

    get_merkle_tree_len(base_tree_leaves, Tree::Arity::to_usize())
}

pub fn get_base_tree_leafs<Tree: MerkleTreeTrait>(base_tree_size: usize) -> Result<usize> {
    get_merkle_tree_leafs(base_tree_size, Tree::Arity::to_usize())
}

#[derive(PartialEq)]
pub enum ProofSystem {
    Groth,
    HaloPallas,
    HaloVesta,
}

pub fn get_proof_system<Tree: MerkleTreeTrait>() -> ProofSystem {
    let field = TypeId::of::<Tree::Field>();
    let fr = TypeId::of::<Fr>();
    let fp = TypeId::of::<Fp>();
    let fq = TypeId::of::<Fq>();
    assert!(field == fr || field == fp || field == fq);
    if field == fr {
        ProofSystem::Groth
    } else if field == fp {
        ProofSystem::HaloPallas
    } else {
        ProofSystem::HaloVesta
    }
}

// A Merkle tree `Store` that does nothing and which is implemented for all `Element` types.
#[derive(Debug)]
pub struct MockStore;

impl<E: Element> Store<E> for MockStore {
    fn new_with_config(_size: usize, _branches: usize, _config: StoreConfig) -> Result<Self> {
        unimplemented!();
    }

    fn new(_size: usize) -> Result<Self> {
        unimplemented!();
    }

    fn new_from_slice_with_config(
        _size: usize,
        _branches: usize,
        _data: &[u8],
        _config: StoreConfig,
    ) -> Result<Self> {
        unimplemented!();
    }

    fn new_from_slice(_size: usize, _data: &[u8]) -> Result<Self> {
        unimplemented!();
    }

    fn new_from_disk(_size: usize, _branches: usize, _config: &StoreConfig) -> Result<Self> {
        unimplemented!();
    }

    fn write_at(&mut self, _el: E, _index: usize) -> Result<()> {
        unimplemented!();
    }

    fn copy_from_slice(&mut self, _buf: &[u8], _start: usize) -> Result<()> {
        unimplemented!();
    }

    fn compact(
        &mut self,
        _branches: usize,
        _config: StoreConfig,
        _store_version: u32,
    ) -> Result<bool> {
        unimplemented!();
    }

    fn reinit(&mut self) -> Result<()> {
        unimplemented!();
    }

    fn delete(_config: StoreConfig) -> Result<()> {
        unimplemented!();
    }

    fn read_at(&self, _index: usize) -> Result<E> {
        unimplemented!();
    }

    fn read_range(&self, _r: std::ops::Range<usize>) -> Result<Vec<E>> {
        unimplemented!();
    }

    fn read_into(&self, _pos: usize, _buf: &mut [u8]) -> Result<()> {
        unimplemented!();
    }

    fn read_range_into(&self, _start: usize, _end: usize, _buf: &mut [u8]) -> Result<()> {
        unimplemented!();
    }

    fn len(&self) -> usize {
        unimplemented!();
    }

    fn loaded_from_disk(&self) -> bool {
        unimplemented!();
    }

    fn is_empty(&self) -> bool {
        unimplemented!();
    }

    fn push(&mut self, _el: E) -> Result<()> {
        unimplemented!();
    }

    fn last(&self) -> Result<E> {
        unimplemented!();
    }

    fn sync(&self) -> Result<()> {
        unimplemented!();
    }

    fn build_small_tree<A: Algorithm<E>, _U: Unsigned>(
        &mut self,
        _leafs: usize,
        _row_count: usize,
    ) -> Result<E> {
        unimplemented!();
    }
}

// A marker trait for arity types that are implemented for all fields.
pub trait PoseidonArityAllFields: PoseidonArity<Fr> + PoseidonArity<Fp> + PoseidonArity<Fq> {}

impl PoseidonArityAllFields for U0 {}
impl PoseidonArityAllFields for U2 {}
impl PoseidonArityAllFields for U8 {}
