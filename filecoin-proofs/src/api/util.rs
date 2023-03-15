use std::fs::OpenOptions;
use std::mem::size_of;
use std::ops::Range;
use std::path::Path;

use anyhow::{Context, Result};
use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher};
use fr32::{bytes_into_fr, fr_into_bytes};
use memmap2::MmapOptions;
use merkletree::merkle::{get_merkle_tree_leafs, get_merkle_tree_len};
use storage_proofs_core::merkle::{get_base_tree_count, MerkleTreeTrait};
use typenum::Unsigned;

use crate::types::{Commitment, SectorSize};

pub fn as_safe_commitment<H: Domain, T: AsRef<str>>(
    comm: &[u8; 32],
    commitment_name: T,
) -> Result<H> {
    bytes_into_fr(comm)
        .map(Into::into)
        .with_context(|| format!("Invalid commitment ({})", commitment_name.as_ref(),))
}

pub fn commitment_from_fr(fr: Fr) -> Commitment {
    let mut commitment = [0; 32];
    for (i, b) in fr_into_bytes(&fr).iter().enumerate() {
        commitment[i] = *b;
    }
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

// Returns a range of nodes read from a sector data/replica file stored at `path`.
pub fn read_nodes_from_file<D: Domain>(path: &Path, node_range: Range<usize>) -> Result<Vec<D>> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("failed to open file: {}", path.display()))?;

    let byte_offset = node_range.start << 5;
    let byte_len = (node_range.end - node_range.start) << 5;
    let bytes = unsafe {
        MmapOptions::new()
            .offset(byte_offset as u64)
            .len(byte_len)
            .map(&file)
            .with_context(|| format!("failed to mmap range of file: {}", path.display()))?
    };

    bytes
        .chunks(32)
        .map(D::try_from_bytes)
        .collect::<Result<Vec<D>>>()
        .with_context(|| "failed to convert file chunk into domain")
}
