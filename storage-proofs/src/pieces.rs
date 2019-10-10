use itertools::Itertools;
use merkletree::merkle::{self, next_pow2};
use merkletree::store::VecStore;
use std::io::Read;

use crate::error::*;
use crate::fr32::Fr32Ary;
use crate::hasher::{Domain, Hasher};
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
        if !self.is_aligned(tree_len) {
            Err(Error::UnalignedPiece)
        } else {
            let packing_list = vec![(0, self.number_of_leaves)];
            Ok((packing_list, self.proof_length(tree_len)))
        }
    }

    pub fn is_aligned(&self, tree_len: usize) -> bool {
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

fn create_piece_tree<H: Hasher>(
    data: &[H::Domain],
) -> merkle::MerkleTree<H::Domain, H::Function, VecStore<H::Domain>> {
    let data_size = data.len();
    // We need to compute comm_p as a merkle root over power-of-two-sized data.
    let tree_size = next_pow2(data_size);

    // If actual data is less than tree size, pad it with zeroes.
    //if data_size < tree_size {
    // NOTE: this assumes that `H::Domain::default()` corresponds to zeroed input.
    // This matters because padding may have been applied at the byte level, using zero bytes.
    merkle::MerkleTree::<H::Domain, H::Function, VecStore<H::Domain>>::new(
        data.iter()
            .cloned()
            .pad_using(tree_size, |_| H::Domain::default()),
    )
}

/// Compute `comm_p` from a slice of Domain elements.
/// `comm_p` is the merkle root of a piece, zero-padded to fill a complete binary sub-tree.
fn compute_piece_commitment<H: Hasher>(data: &[H::Domain]) -> H::Domain {
    create_piece_tree::<H>(data).root()
}

/// Generate `comm_p` from a source and return it as bytes.
pub fn generate_piece_commitment_bytes_from_source<H: Hasher>(
    source: &mut dyn Read,
) -> Result<Fr32Ary> {
    let mut domain_data = Vec::new();
    let mut total_bytes_read = 0;

    let mut buf = [0; NODE_SIZE];

    loop {
        let bytes_read = source.read(&mut buf)?;
        total_bytes_read += bytes_read;
        if bytes_read > 0 {
            domain_data.push(<H::Domain as Domain>::try_from_bytes(&buf[..bytes_read])?);
        } else {
            break;
        }
    }

    if total_bytes_read < NODE_SIZE {
        return Err(Error::Unclassified(
            "insufficient data to generate piece commitment".to_string(),
        ));
    }

    let mut comm_p_bytes = [0; NODE_SIZE];
    let comm_p = compute_piece_commitment::<H>(&domain_data);
    comm_p.write_bytes(&mut comm_p_bytes)?;

    Ok(comm_p_bytes)
}

////////////////////////////////////////////////////////////////////////////////
// Utility

pub fn piece_is_aligned(position: usize, length: usize, tree_len: usize) -> bool {
    let capacity_at_pos = subtree_capacity(position, tree_len);

    capacity_at_pos.is_power_of_two() && capacity_at_pos >= length
}

fn height_for_length(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (n as f64).log2().ceil() as usize
    }
}

fn subtree_capacity(pos: usize, total: usize) -> usize {
    assert!(pos < total, "position must be less than tree capacity");

    let mut capacity = 1;
    // If tree is not 'full', then pos 0 will have subtree_capacity greater than size of tree.
    let mut cursor = pos + next_pow2(total);

    while cursor & 1 == 0 {
        capacity *= 2;
        cursor >>= 1;
    }
    capacity
}
////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasher::PedersenHasher;

    #[test]
    fn test_subtree_capacity() {
        assert_eq!(subtree_capacity(0, 16), 16);
        assert_eq!(subtree_capacity(1, 16), 1);
        assert_eq!(subtree_capacity(2, 16), 2);
        assert_eq!(subtree_capacity(3, 16), 1);
        assert_eq!(subtree_capacity(4, 16), 4);
        assert_eq!(subtree_capacity(5, 16), 1);
        assert_eq!(subtree_capacity(6, 16), 2);
        assert_eq!(subtree_capacity(7, 16), 1);
        assert_eq!(subtree_capacity(8, 16), 8);
        assert_eq!(subtree_capacity(9, 16), 1);
        assert_eq!(subtree_capacity(10, 16), 2);
        assert_eq!(subtree_capacity(11, 16), 1);
        assert_eq!(subtree_capacity(12, 16), 4);
        assert_eq!(subtree_capacity(13, 16), 1);
        assert_eq!(subtree_capacity(14, 16), 2);
        assert_eq!(subtree_capacity(15, 16), 1);
    }

    #[test]
    fn test_generate_piece_commitment_bytes_from_source() -> Result<()> {
        let some_bytes: Vec<u8> = vec![0; 64];
        let mut some_bytes_slice: &[u8] = &some_bytes;
        generate_piece_commitment_bytes_from_source::<PedersenHasher>(&mut some_bytes_slice)
            .expect("threshold for sufficient bytes is 32");

        let not_enough_bytes: Vec<u8> = vec![0; 7];
        let mut not_enough_bytes_slice: &[u8] = &not_enough_bytes;
        assert!(
            generate_piece_commitment_bytes_from_source::<PedersenHasher>(
                &mut not_enough_bytes_slice
            )
            .is_err(),
            "insufficient bytes should error out"
        );

        Ok(())
    }
}
