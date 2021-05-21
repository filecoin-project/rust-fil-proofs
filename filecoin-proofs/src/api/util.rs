use anyhow::{Context, Result};
use bellperson::bls::Fr;
use merkletree::merkle::{get_merkle_tree_leafs, get_merkle_tree_len};
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes};
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::merkle::{get_base_tree_count, MerkleTreeTrait};
use typenum::Unsigned;

use crate::types::{Commitment, SectorSize};

pub(crate) fn as_safe_commitment<H: Domain, T: AsRef<str>>(
    comm: &[u8; 32],
    commitment_name: T,
) -> Result<H> {
    bytes_into_fr(comm)
        .map(Into::into)
        .with_context(|| format!("Invalid commitment ({})", commitment_name.as_ref(),))
}

pub(crate) fn commitment_from_fr(fr: Fr) -> Commitment {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
    commitment
}

pub(crate) fn get_base_tree_size<Tree: MerkleTreeTrait>(sector_size: SectorSize) -> Result<usize> {
    let base_tree_leaves = u64::from(sector_size) as usize
        / std::mem::size_of::<<Tree::Hasher as Hasher>::Domain>()
        / get_base_tree_count::<Tree>();

    get_merkle_tree_len(base_tree_leaves, Tree::Arity::to_usize())
}

pub(crate) fn get_base_tree_leafs<Tree: MerkleTreeTrait>(base_tree_size: usize) -> Result<usize> {
    get_merkle_tree_leafs(base_tree_size, Tree::Arity::to_usize())
}
