use std::marker::PhantomData;

use merkle_light::hash::Algorithm;
use merkle_light::proof::Proof;

use crate::error::*;
use crate::hasher::{Domain, Hasher};
use crate::merkle::MerkleTree;

type InclusionProof<T> = Proof<T>;

/// A FileInclusionProof contains a merkle inclusion proof for the first and last node
/// of a piece. This ensures all 'edge' hashes necessary to generate a complete merkle
/// tree are available.
///
/// Depending on the position of the nodes, not every hash provided will actually be needed.
/// As a space optimization, and at the cost of greater complexity in the encoding, 'interior' nodes
/// of either path may be omitted.
pub struct PieceInclusionProof<H: Hasher> {
    first_node_proof: InclusionProof<H::Domain>,
    last_node_proof: InclusionProof<H::Domain>,
    _h: PhantomData<H>,
}

/// file_inclusion_proofs takes a merkle tree and a slice of piece lengths, and returns
/// a vector of file inclusion proofs corresponding to the pieces. This assumes that the first
/// piece begins at offset 0, and that each piece begins directly after the previous piece ends.
/// For this method to work, the piece data used to validate pieces will need to be padded as necessary,
/// and pieces will need to be aligned (to 128-byte chunks for Fr32 bit-padding) when written.
pub fn file_inclusion_proofs<H: Hasher>(
    tree: &MerkleTree<H::Domain, H::Function>,
    piece_lengths: &[usize],
) -> Vec<PieceInclusionProof<H>> {
    bounds(piece_lengths)
        .iter()
        .map(|(start, end)| file_inclusion_proof(tree, *start, end - 1))
        .collect()
}

// Given a set of lengths, return corresponding (start, end) pairs for successive pieces.
fn bounds(lengths: &[usize]) -> Vec<(usize, usize)> {
    let mut start = 0;
    let mut bounds = Vec::with_capacity(lengths.len());
    for length in lengths {
        let end = start + length;
        bounds.push((start, end));
        start = end;
    }
    bounds
}

/// file_inclusion_proof takes a merkle tree and the index positions of the first and last nodes
/// of the piece whose inclusion should be proved. It returns a corresponding file_inclusion_proof.
/// For the resulting proof to be valid, first_node must be <= last_node.
pub fn file_inclusion_proof<H: Hasher>(
    tree: &MerkleTree<H::Domain, H::Function>,
    first_node: usize,
    last_node: usize,
) -> PieceInclusionProof<H> {
    PieceInclusionProof {
        first_node_proof: tree.gen_proof(first_node),
        last_node_proof: tree.gen_proof(last_node),
        _h: PhantomData,
    }
}

impl<H: Hasher> PieceInclusionProof<H> {
    /// verify takes a merkle root and (pre-processed) piece data.
    /// Iff it returns true, then FileInclusionProof indeed proves that piece's
    /// bytes were included in the merkle tree corresponding to root -- and at the
    /// position encoded in the proof.
    fn verify(&self, root: &H::Domain, piece: &[u8]) -> bool {
        // These checks are superfluous but inexpensive and clarifying.
        if !(self.first_node_proof.validate::<H::Function>()
            && self.last_node_proof.validate::<H::Function>())
        {
            return false;
        }
        // If the computed root is equal to the provided root, then the piece was provably
        // present in the data from which the merkle tree was constructed.
        match compute_root::<H>(&self.first_node_proof, &self.last_node_proof, piece) {
            Ok(computed_root) => *root == computed_root,
            Err(_) => false,
        }
    }
}

/// Compute the root which results when hashing the supplied piece_data, supplemented by the hashes
/// in the left (first) and right (last) inclusion proofs from the FileInclusionProof.
fn compute_root<H: Hasher>(
    left_proof: &InclusionProof<H::Domain>,
    right_proof: &InclusionProof<H::Domain>,
    piece_data: &[u8],
) -> Result<H::Domain> {
    // Zip the left and right proof_vecs into one.
    let proof_vecs = proof_vec(left_proof).zip(proof_vec(right_proof));

    let mut hasher = H::Function::default();

    let mut last_row = Vec::new();

    for chunk in piece_data.chunks(32) {
        last_row.push(H::Domain::try_from_bytes(chunk)?);
    }

    for (height, ((l_hash, l_is_left), (r_hash, r_is_left))) in proof_vecs.enumerate() {
        let mut row = Vec::new();
        if !*l_is_left {
            row.push(*l_hash);
        };
        row.extend(last_row);
        if *r_is_left {
            row.push(*r_hash);
        }
        last_row = hash_pairs::<H>(&mut hasher, row.as_slice(), height)?;
    }
    assert_eq!(last_row.len(), 1);
    Ok(last_row[0])
}

/// For each successive pair of input hashes in row, construct a new hash according to the method used by `hasher.node`,
/// returning a vector of the constructed hashes, in order.
/// The result will be an error (resulting in a failed proof) if row does not contain an even number of hashes.
fn hash_pairs<H: Hasher>(
    hasher: &mut H::Function,
    row: &[H::Domain],
    height: usize,
) -> Result<Vec<H::Domain>> {
    let hashed: Result<Vec<_>> = row
        .chunks(2)
        .map(|pair| {
            if pair.len() != 2 {
                // If input is malformed, return an Err, which will fail the proof.
                return Err(Error::MalformedInput);
            }
            hasher.reset();
            Ok(hasher.node(pair[0], pair[1], height))
        })
        .collect();

    hashed
}

/// Return a vector of (hash, bool) pairs, where the bool indicates whether the paired hash
/// will be the left child of the next node hashed. In order to accomplish this, we skip
/// the first hash provided (in proof.lemma()). This is an implementation detail of how a
/// merkle_light::proof::Proof is structured.
fn proof_vec<T: Domain>(proof: &Proof<T>) -> impl Iterator<Item = (&T, &bool)> {
    proof.lemma().iter().skip(1).zip(proof.path().iter())
}

/// verify_file_inclusion_proofs returns true iff each provided piece is proved with respect to root
/// by the corresponding (by index) proof.
pub fn verify_file_inclusion_proofs<H: Hasher>(
    root: &H::Domain,
    proofs: &[PieceInclusionProof<H>],
    pieces: &[&[u8]],
) -> bool {
    proofs
        .iter()
        .zip(pieces)
        .all(|(proof, piece)| proof.verify(root, piece))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};

    const NODE_BYTES: usize = 32;

    #[test]
    fn compute_bounds() {
        assert_eq!(bounds(&[3, 5, 7, 9]), [(0, 3), (3, 8), (8, 15), (15, 24)]);
    }

    #[test]
    fn file_inclusion_proof_pedersen() {
        test_file_inclusion_proof::<PedersenHasher>();
    }

    #[test]
    fn file_inclusion_proof_sha256() {
        test_file_inclusion_proof::<Sha256Hasher>();
    }

    #[test]
    fn file_inclusion_proof_blake2s() {
        test_file_inclusion_proof::<Blake2sHasher>();
    }

    fn test_file_inclusion_proof<H: Hasher>() {
        let nodes = 5;
        for i in 1..nodes {
            for j in 1..(nodes - i) {
                file_inclusion_proof_aux::<H>(nodes, &[i, j]);
            }
        }

        file_inclusion_proof_aux::<H>(32, &[32usize]);
        file_inclusion_proof_aux::<H>(32, &[10usize, 15, 7]);
        file_inclusion_proof_aux::<H>(32, &[3usize, 9, 20]);
        file_inclusion_proof_aux::<H>(32, &[4usize, 6, 14]);
    }

    fn file_inclusion_proof_aux<H: Hasher>(nodes: usize, node_lengths: &[usize]) {
        let size = nodes * NODE_BYTES;
        let g = BucketGraph::<H>::new(nodes, 0, 0, new_seed());
        let mut data = Vec::<u8>::with_capacity(nodes);

        for i in 0..size {
            data.push(
                (((i / NODE_BYTES) + i)
                // Mask out two most significant bits so we will always be Fr32,
                & 63) as u8,
            )
        }

        let tree = g.merkle_tree(&data).unwrap();
        let lengths: Vec<usize> = node_lengths.iter().map(|x| x * 32).collect();

        let proofs = file_inclusion_proofs::<H>(&tree, &node_lengths);
        let bounds = bounds(lengths.as_slice());
        let mut pieces = Vec::new();
        for (start, end) in &bounds {
            pieces.push(&data[*start..*end])
        }

        assert_eq!(
            true,
            verify_file_inclusion_proofs(&tree.root(), &proofs, &pieces),
        );

        let mut wrong_data = Vec::<u8>::with_capacity(size);
        let mut wrong_pieces = Vec::new();

        for i in 0..size {
            wrong_data.push(
                ((i / NODE_BYTES) + (2 * i)
                // Mask out two most significant bits so we will always be Fr32,
                & 63) as u8,
            )
        }

        for (start, end) in &bounds {
            wrong_pieces.push(&wrong_data[*start..*end])
        }

        assert_eq!(
            false,
            verify_file_inclusion_proofs(&tree.root(), &proofs, &wrong_pieces),
        )
    }
}
