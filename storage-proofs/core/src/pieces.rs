use std::io::Read;

use anyhow::{ensure, Context};
use merkletree::merkle::next_pow2;

use crate::error::*;
use crate::fr32::Fr32Ary;
use crate::hasher::{Domain, Hasher};
use crate::merkle::BinaryMerkleTree;
use crate::util::NODE_SIZE;

/// `position`, `length` are in H::Domain units
#[derive(Clone, Debug)]
pub struct PieceSpec {
    pub comm_p: Fr32Ary,
    pub position: usize,
    pub number_of_leaves: usize,
}

impl PieceSpec {
    /// `compute_packing` returns a packing list and a proof size.
    /// A packing list is a pair of (start, length) pairs, relative to the beginning of the piece,
    /// in leaf units.
    /// Proof size is a number of elements (size same as one leaf) provided in the variable part of a PieceInclusionProof.
    pub fn compute_packing(&self, tree_len: usize) -> Result<(Vec<(usize, usize)>, usize)> {
        ensure!(self.is_aligned(tree_len)?, Error::UnalignedPiece);

        let packing_list = vec![(0, self.number_of_leaves)];
        Ok((packing_list, self.proof_length(tree_len)))
    }

    pub fn is_aligned(&self, tree_len: usize) -> Result<bool> {
        piece_is_aligned(self.position, self.number_of_leaves, tree_len)
    }

    fn height(&self) -> usize {
        height_for_length(self.number_of_leaves)
    }

    // `proof_length` is length of proof that comm_p is in the containing root, excluding comm_p and root, which aren't needed for the proof itself.
    fn proof_length(&self, tree_len: usize) -> usize {
        height_for_length(tree_len) - self.height()
    }
}

/// Generate `comm_p` from a source and return it as bytes.
pub fn generate_piece_commitment_bytes_from_source<H: Hasher>(
    source: &mut dyn Read,
    padded_piece_size: usize,
) -> Result<Fr32Ary> {
    ensure!(padded_piece_size > 32, "piece is too small");
    ensure!(padded_piece_size % 32 == 0, "piece is not valid size");

    let mut buf = [0; NODE_SIZE];

    let parts = (padded_piece_size as f64 / NODE_SIZE as f64).ceil() as usize;

    let tree = BinaryMerkleTree::<H>::try_from_iter((0..parts).map(|_| {
        source.read_exact(&mut buf)?;
        <H::Domain as Domain>::try_from_bytes(&buf).context("invalid Fr element")
    }))
    .context("failed to build tree")?;

    let mut comm_p_bytes = [0; NODE_SIZE];
    let comm_p = tree.root();
    comm_p.write_bytes(&mut comm_p_bytes)?;

    Ok(comm_p_bytes)
}

////////////////////////////////////////////////////////////////////////////////
// Utility

pub fn piece_is_aligned(position: usize, length: usize, tree_len: usize) -> Result<bool> {
    let capacity_at_pos = subtree_capacity(position, tree_len)?;

    Ok(capacity_at_pos.is_power_of_two() && capacity_at_pos >= length)
}

fn height_for_length(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (n as f64).log2().ceil() as usize
    }
}

fn subtree_capacity(pos: usize, total: usize) -> Result<usize> {
    ensure!(pos < total, "position must be less than tree capacity");

    let mut capacity = 1;
    // If tree is not 'full', then pos 0 will have subtree_capacity greater than size of tree.
    let mut cursor = pos + next_pow2(total);

    while cursor & 1 == 0 {
        capacity *= 2;
        cursor >>= 1;
    }
    Ok(capacity)
}
////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::PoseidonHasher;

    #[test]
    fn test_subtree_capacity() {
        assert_eq!(subtree_capacity(0, 16).unwrap(), 16);
        assert_eq!(subtree_capacity(1, 16).unwrap(), 1);
        assert_eq!(subtree_capacity(2, 16).unwrap(), 2);
        assert_eq!(subtree_capacity(3, 16).unwrap(), 1);
        assert_eq!(subtree_capacity(4, 16).unwrap(), 4);
        assert_eq!(subtree_capacity(5, 16).unwrap(), 1);
        assert_eq!(subtree_capacity(6, 16).unwrap(), 2);
        assert_eq!(subtree_capacity(7, 16).unwrap(), 1);
        assert_eq!(subtree_capacity(8, 16).unwrap(), 8);
        assert_eq!(subtree_capacity(9, 16).unwrap(), 1);
        assert_eq!(subtree_capacity(10, 16).unwrap(), 2);
        assert_eq!(subtree_capacity(11, 16).unwrap(), 1);
        assert_eq!(subtree_capacity(12, 16).unwrap(), 4);
        assert_eq!(subtree_capacity(13, 16).unwrap(), 1);
        assert_eq!(subtree_capacity(14, 16).unwrap(), 2);
        assert_eq!(subtree_capacity(15, 16).unwrap(), 1);
    }

    #[test]
    fn test_generate_piece_commitment_bytes_from_source() -> Result<()> {
        let some_bytes: Vec<u8> = vec![0; 64];
        let mut some_bytes_slice: &[u8] = &some_bytes;
        generate_piece_commitment_bytes_from_source::<PoseidonHasher>(&mut some_bytes_slice, 64)
            .expect("threshold for sufficient bytes is 32");

        let not_enough_bytes: Vec<u8> = vec![0; 7];
        let mut not_enough_bytes_slice: &[u8] = &not_enough_bytes;
        assert!(
            generate_piece_commitment_bytes_from_source::<PoseidonHasher>(
                &mut not_enough_bytes_slice,
                7
            )
            .is_err(),
            "insufficient bytes should error out"
        );

        Ok(())
    }
}
