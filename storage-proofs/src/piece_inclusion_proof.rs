use itertools::Itertools;
use merkletree::hash::Algorithm;
use merkletree::merkle::{self, next_pow2, VecStore};

use crate::error::*;
use crate::fr32::Fr32Vec;
use crate::hasher::{Domain, Hasher};
use crate::merkle::MerkleTree;

/// Based on the alignment information (and sector size, provided during verification),
/// the algorithm deterministically consumes the elements.
#[derive(Clone, Debug)]
pub struct PieceInclusionProof<H: Hasher> {
    position: usize,
    piece_leaves: usize,
    proof_elements: Vec<H::Domain>,
}

/// `position`, `length` are in H::Domain units
#[derive(Clone, Debug)]
pub struct PieceSpec<'a> {
    comm_p: &'a Fr32Vec,
    position: usize,
    length: usize,
}

impl<'a> PieceSpec<'a> {
    /// `compute_packing` returns a packing list and a proof size.
    /// A packing list is a pair of (start, length) pairs, relative to the beginning of the piece,
    /// in leaf units.
    /// Proof size is a number of elements (size same as one leaf) provided in the variable part of a PieceInclusionProof.
    pub fn compute_packing(&self, tree_len: usize) -> Result<(Vec<(usize, usize)>, usize)> {
        if !self.is_aligned(tree_len) {
            Err(Error::UnalignedPiece)
        } else {
            let packing_list = vec![(0, self.length)];
            Ok((packing_list, self.proof_length(tree_len)))
        }
    }

    pub fn is_aligned(&self, tree_len: usize) -> bool {
        piece_is_aligned(self.position, self.length, tree_len)
    }

    fn height(&self) -> usize {
        height_for_length(self.length)
    }

    // `proof_length` is length of proof that comm_p is in the containing root, excluding comm_p and root, which aren't needed for the proof itself.
    fn proof_length(&self, tree_len: usize) -> usize {
        height_for_length(tree_len) - self.height()
    }
}

#[allow(dead_code)]
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

#[allow(dead_code)]
/// Compute `comm_p` from a slice of Domain elements.
/// `comm_p` is the merkle root of a piece, zero-padded to fill a complete binary sub-tree.
fn compute_piece_commitment<H: Hasher>(data: &[H::Domain]) -> H::Domain {
    create_piece_tree::<H>(data).root()
}

#[allow(dead_code)]
/// Generate `comm_p` from bytes
fn generate_piece_commitment<H: Hasher>(data: &[u8]) -> Result<H::Domain> {
    let mut domain_data = Vec::new();
    for d in data.chunks(32) {
        domain_data.push(<H::Domain as Domain>::try_from_bytes(d)?)
    }

    Ok(compute_piece_commitment::<H>(&domain_data))
}

#[allow(dead_code)]
/// Generate `comm_p` from bytes and return it as bytes.
fn generate_piece_commitment_bytes<H: Hasher>(data: &[u8]) -> Result<Fr32Vec> {
    let comm_p = generate_piece_commitment::<H>(data)?;

    Ok(H::Domain::into_bytes(&comm_p))
}

pub fn piece_inclusion_proofs<H: Hasher>(
    piece_specs: &[PieceSpec],
    tree: &MerkleTree<H::Domain, H::Function>,
) -> Result<Vec<PieceInclusionProof<H>>> {
    piece_specs
        .iter()
        .map(|piece_spec| PieceInclusionProof::new(piece_spec.clone(), tree))
        .collect()
}

impl<H: Hasher> PieceInclusionProof<H> {
    pub fn new(
        piece_spec: PieceSpec,
        tree: &MerkleTree<H::Domain, H::Function>,
    ) -> Result<PieceInclusionProof<H>> {
        let PieceSpec {
            comm_p,
            position: first_leaf,
            length: leaf_count,
        } = piece_spec;

        let last_leaf = first_leaf + (leaf_count - 1);

        // For now, we only handled aligned pieces.
        if !piece_spec.is_aligned(tree.len()) {
            return Err(Error::UnalignedPiece);
        }

        let first_proof = tree.gen_proof(first_leaf);
        let last_proof = tree.gen_proof(last_leaf);

        // Including first leaf (item).
        let proof_length = piece_spec.height() + 1;

        // Find the first common hash (at same position) in first and last proof,
        // then discard all previous hashes and path bits, and create a new proof containing
        // only the common part.
        //
        // For an aligned piece, there is guaranteed to be a common element.
        // That is, the merkle root of the piece must be a node of the tree (and therefore in the paths
        // of all leaves of the piece (including the first and last).
        for (i, (a, b)) in first_proof
            .lemma()
            .iter()
            .zip(last_proof.lemma().iter())
            .enumerate()
        {
            if (a == b) && (i == proof_length) {
                let proof_elements = first_proof.lemma()[i..first_proof.lemma().len() - 1].to_vec();

                let piece_inclusion_proof = PieceInclusionProof {
                    proof_elements,
                    position: first_leaf,
                    piece_leaves: leaf_count,
                };

                if piece_inclusion_proof.verify(
                    &tree.root(),
                    &H::Domain::try_from_bytes(comm_p)?,
                    leaf_count,
                    tree.leafs(),
                ) {
                    return Ok(piece_inclusion_proof);
                } else {
                    return Err(Error::BadPieceCommitment);
                }
            }
        }

        // There must be a common root, if only the root of the entire tree.
        Err(Error::MalformedMerkleTree)
    }

    fn leaf_path(leaf: usize, tree_height: usize) -> Vec<bool> {
        let mut height = tree_height;
        let mut rising_leaf = leaf;
        let mut path = Vec::new();

        while height > 0 {
            // If this leaf's least significant bit is set, then it is a right branch, so `is_right` is true.
            path.push(rising_leaf & 1 == 1);
            rising_leaf >>= 1;
            height -= 1;
        }
        path
    }

    /// verify takes a merkle root and (pre-processed) piece data.
    /// Iff it returns true, then PieceInclusionProof indeed proves that piece's
    /// bytes were included in the merkle tree corresponding to root -- and at the
    /// position encoded in the proof.
    /// `piece_leaves` and `sector_leaves` are in units of `Domain` (i.e. `NODE_SIZE` = 32 bytes).

    fn verify(
        &self,
        root: &H::Domain,
        comm_p: &H::Domain,
        piece_leaves: usize,
        sector_leaves: usize,
    ) -> bool {
        let sector_height = height_for_length(sector_leaves);
        let piece_height = height_for_length(piece_leaves);
        let proof_length = sector_height - piece_height;

        let proof_path = &Self::leaf_path(self.position, sector_height)[piece_height..];

        // This is an important check. Without it, a fake proof could have a longer path and prove less data.
        // In the most extreme case, this would mean storing `comm_p` itself as a leaf node.
        // This check ensures `comm_p` appears at the right height in the tree.
        if (proof_path.len() != proof_length) || self.proof_elements.len() != proof_length {
            return false;
        }

        if piece_leaves != self.piece_leaves {
            return false;
        }

        Self::validate_inclusion(
            *root,
            *comm_p,
            &self.proof_elements,
            proof_path,
            piece_height,
        )
    }

    /// Validates the MerkleProof and that it corresponds to the supplied node.
    /// Node height must be supplied, since `validate_inclusion` can prove inclusion
    /// of nodes which are not leaves. `node_height` is 0 for a leaf node.
    fn validate_inclusion(
        root: H::Domain,
        node: H::Domain,
        elements: &[H::Domain],
        path: &[bool],
        node_height: usize,
    ) -> bool {
        let mut a = H::Function::default();

        root == (0..path.len()).fold(node, |h, i| {
            a.reset();
            let is_right = path[i];

            let (left, right) = if is_right {
                (elements[i], h)
            } else {
                (h, elements[i])
            };

            a.node(left, right, i + node_height)
        })
    }

    /// verify_piece_inclusion_proofs returns true iff each provided piece is proved with respect to root
    /// by the corresponding (by index) proof.
    pub fn verify_all(
        root: &[u8],
        proofs: &[PieceInclusionProof<H>],
        comm_ps: &[Vec<u8>],
        piece_sizes: &[usize],
        sector_size: usize,
    ) -> Result<bool> {
        let root_domain = H::Domain::try_from_bytes(root)?;

        Ok(proofs.iter().zip(comm_ps.iter().zip(piece_sizes)).all(
            |(proof, (comm_p, piece_size))| {
                proof.verify(
                    &root_domain,
                    &H::Domain::try_from_bytes(comm_p).unwrap(),
                    *piece_size,
                    sector_size,
                )
            },
        ))
    }
}

////////////////////////////////////////////////////////////////////////////////
// Utility

pub fn piece_is_aligned(position: usize, length: usize, tree_len: usize) -> bool {
    let capacity_at_pos = subtree_capacity(position, tree_len);

    is_pow2(capacity_at_pos) && capacity_at_pos >= length
}

fn height_for_length(n: usize) -> usize {
    (n as f64).log2().ceil() as usize
}

fn is_pow2(n: usize) -> bool {
    n.count_ones() == 1
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
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::util::NODE_SIZE;

    #[test]
    fn piece_inclusion_proof_pedersen() {
        test_piece_inclusion_proof::<PedersenHasher>();
    }

    #[test]
    fn piece_inclusion_proof_sha256() {
        test_piece_inclusion_proof::<Sha256Hasher>();
    }

    #[test]
    fn piece_inclusion_proof_blake2s() {
        test_piece_inclusion_proof::<Blake2sHasher>();
    }

    fn test_piece_inclusion_proof<H: Hasher>() {
        let mut size = 32;

        test_piece_inclusion_proof_aux::<H>(32, &[32], &[0], false);

        //        // Aligned proofs
        while size > 2 {
            for i in 2..size {
                test_piece_inclusion_proof_aux::<H>(size, &[i], &[0], false);
            }

            size >>= 1;
        }

        //        // Unaligned proof (should fail)
        test_piece_inclusion_proof_aux::<H>(32, &[16usize], &[8usize], true);

        //        // Mixed aligned and unaligned
        for i in 0..16 {
            test_piece_inclusion_proof_aux::<H>(32, &[8usize], &[i], i % 8 != 0);
        }

        // TODO: when unaligned proofs are supported, test more exhaustively.
    }

    fn test_piece_inclusion_proof_aux<H: Hasher>(
        nodes: usize,
        node_lengths: &[usize],
        start_positions: &[usize],
        expect_alignment_error: bool,
    ) {
        assert_eq!(node_lengths.len(), 1); // For now.
        let size = nodes * NODE_SIZE;
        let g = BucketGraph::<H>::new(nodes, 0, 0, new_seed());
        let mut data = vec![0u8; size]; //Vec::<u8>::with_capacity(nodes);

        let data_size = node_lengths[0] * NODE_SIZE;

        for i in 0..data_size {
            data[i] = (((i / NODE_SIZE) + i)
                // Mask out two most significant bits so we will always be Fr32,
                & 63) as u8;
        }

        let tree = g.merkle_tree(&data).unwrap();

        let mut pieces = Vec::new();
        let mut comm_ps = Vec::new();

        let sections: Vec<_> = start_positions
            .iter()
            .zip(node_lengths)
            .map(|(pos, length)| (*pos, *length))
            .collect();

        for (start, length) in &sections {
            let piece = &data[*start * NODE_SIZE..(*start + *length) * NODE_SIZE];
            pieces.push(piece);
            let comm_p = generate_piece_commitment_bytes::<H>(piece);
            comm_ps.push(comm_p.unwrap());
        }

        let piece_tree = create_piece_tree::<H>(
            &data
                .chunks(32)
                .map(|x| H::Domain::try_from_bytes(x).unwrap())
                .collect::<Vec<_>>(),
        );
        assert_eq!(tree.leafs(), piece_tree.leafs());

        let mut piece_specs = Vec::new();
        for (comm_p, (position, length)) in comm_ps.iter().zip(sections.clone()) {
            piece_specs.push(PieceSpec {
                comm_p: &comm_p,
                position,
                length,
            })
        }

        let proofs = piece_inclusion_proofs::<H>(&piece_specs, &tree);

        if expect_alignment_error {
            assert!(proofs.is_err());
        } else {
            let proofs = proofs.unwrap();
            for (proof, piece_spec) in proofs.iter().zip(piece_specs.clone()) {
                let (_, proof_length) = piece_spec.compute_packing(nodes).unwrap();
                assert_eq!(proof.proof_elements.len(), proof_length);
            }

            assert_eq!(
                true,
                PieceInclusionProof::verify_all(
                    &tree.root().into_bytes(),
                    proofs.as_slice(),
                    &comm_ps,
                    &node_lengths,
                    nodes,
                )
                .unwrap()
            );
        }

        if !expect_alignment_error {
            let proofs = piece_inclusion_proofs::<H>(&piece_specs, &tree);

            let mut wrong_data = Vec::<u8>::with_capacity(size);
            let mut wrong_pieces = Vec::new();
            let mut wrong_comm_ps = Vec::new();
            for i in 0..size {
                wrong_data.push(
                    ((i / NODE_SIZE) + (2 * i)
                        // Mask out two most significant bits so we will always be Fr32,
                        & 63) as u8,
                )
            }

            for (start, length) in &sections {
                let wrong_piece = &wrong_data[*start * NODE_SIZE..(*start + *length) * NODE_SIZE];
                wrong_pieces.push(wrong_piece);
                wrong_comm_ps.push(generate_piece_commitment_bytes::<H>(wrong_piece).unwrap());
            }

            assert_eq!(
                false,
                PieceInclusionProof::verify_all(
                    &tree.root().into_bytes(),
                    &proofs.unwrap(),
                    &wrong_comm_ps,
                    &node_lengths,
                    nodes
                )
                .unwrap(),
            )
        }
    }

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
}
