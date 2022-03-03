use std::mem::size_of;

use anyhow::{Context, Result};
use ff::PrimeField;
use filecoin_hashers::{Domain, Hasher};
use merkletree::merkle::{get_merkle_tree_leafs, get_merkle_tree_len};
use storage_proofs_core::merkle::{get_base_tree_count, MerkleTreeTrait};
use typenum::Unsigned;

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
