use std::convert::TryFrom;

use itertools::{izip, Itertools};
use merkletree::hash::Algorithm;
use merkletree::merkle::next_pow2;
use std::io::Read;

use crate::error::*;
use crate::fr32::Fr32Ary;
use crate::hasher::hybrid::HybridDomain;
use crate::hasher::{Domain, Hasher};
use crate::hybrid_merkle::HybridMerkleTree;
use crate::util::NODE_SIZE;

// 8 bytes for `PieceInclusionProof.position` (the standard size of a `usize`).
// TODO: don't use 8 as the magic size for `usize`.
const NUM_PIP_HEADER_BYTES: usize = 8;

/// Based on the alignment information (and sector size, provided during verification),
/// the algorithm deterministically consumes the elements.
#[derive(Clone, Debug)]
pub struct PieceInclusionProof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    position: usize,
    proof_elements: Vec<HybridDomain<AH::Domain, BH::Domain>>,
}

impl<AH, BH> From<PieceInclusionProof<AH, BH>> for Vec<u8>
where
    AH: Hasher,
    BH: Hasher,
{
    fn from(proof: PieceInclusionProof<AH, BH>) -> Self {
        let position = proof.position.to_le_bytes();
        let proof_elements = proof
            .proof_elements
            .iter()
            .flat_map(HybridDomain::into_bytes)
            .collect::<Vec<u8>>();

        [&position, proof_elements.as_slice()].concat()
    }
}

impl<AH, BH> TryFrom<&[u8]> for PieceInclusionProof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    type Error = failure::Error;

    fn try_from(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        // TODO: maybe option in a function, not a from
        // also don't use 8 as the magic number from usize
        if bytes.len() < NUM_PIP_HEADER_BYTES
            || (bytes.len() - NUM_PIP_HEADER_BYTES) % NODE_SIZE != 0
        {
            return Err(format_err!("malformed piece inclusion proof"));
        }

        let mut position_bytes: [u8; 8] = [0; 8];
        position_bytes.copy_from_slice(&bytes[0..8]);

        let mut proof_elements = Vec::new();

        for chunk in bytes[NUM_PIP_HEADER_BYTES..].chunks(NODE_SIZE) {
            // All nodes in the data layer's tree are `HybridDomain::Beta`.
            let element_beta = <BH::Domain as Domain>::try_from_bytes(&chunk)?;
            let element = HybridDomain::Beta(element_beta);
            proof_elements.push(element);
        }

        Ok(Self {
            position: usize::from_le_bytes(position_bytes),
            proof_elements,
        })
    }
}

/// A piece spans a range of leaves, the number of leaves in that range is given by
/// `number_of_leaves`. `position` is the first leaf in that range. `position` and
/// `number_of_leaves` are in units of `HybridDomain`.
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

fn create_piece_tree<AH, BH>(
    data: &[HybridDomain<AH::Domain, BH::Domain>],
) -> HybridMerkleTree<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    let data_size = data.len();
    // We need to compute comm_p as a merkle root over power-of-two-sized data.
    let tree_size = next_pow2(data_size);

    // If actual data is less than tree size, pad it with zeroes.
    // NOTE: this assumes that `H::Domain::default()` corresponds to zeroed input. This matters
    // because padding may have been applied at the byte level, using zero bytes.
    let data = data
        .iter()
        .cloned()
        .pad_using(tree_size, |_| HybridDomain::Beta(BH::Domain::default()));

    // The data layer's beta height is always the tree's height.
    let beta_height = (tree_size as f32).log2() as usize + 1;
    HybridMerkleTree::from_leaves(data, beta_height)
}

/// Compute `comm_p` from a slice of Domain elements.  `comm_p` is the merkle root of a piece,
/// zero-padded to fill a complete binary sub-tree.
fn compute_piece_commitment<AH, BH>(
    data: &[HybridDomain<AH::Domain, BH::Domain>],
) -> HybridDomain<AH::Domain, BH::Domain>
where
    AH: Hasher,
    BH: Hasher,
{
    create_piece_tree::<AH, BH>(data).root()
}

/// Generate `comm_p` from a source and return it as bytes.
pub fn generate_piece_commitment_bytes_from_source<AH, BH>(source: &mut dyn Read) -> Result<Fr32Ary>
where
    AH: Hasher,
    BH: Hasher,
{
    let mut domain_data: Vec<HybridDomain<AH::Domain, BH::Domain>> = vec![];
    let mut total_bytes_read = 0;

    loop {
        let mut buf = [0; NODE_SIZE];

        let bytes_read = source.read(&mut buf)?;
        total_bytes_read += bytes_read;

        if bytes_read == 0 {
            break;
        }

        // Leaves in the data layer are always `HybridDomain::Beta`.
        let leaf_beta = <BH::Domain as Domain>::try_from_bytes(&buf)?;
        let leaf = HybridDomain::Beta(leaf_beta);
        domain_data.push(leaf);
    }

    if total_bytes_read < NODE_SIZE {
        return Err(Error::Unclassified(
            "insufficient data to generate piece commitment".to_string(),
        ));
    }

    let mut comm_p_bytes = [0; NODE_SIZE];
    let comm_p = compute_piece_commitment::<AH, BH>(&domain_data);
    comm_p.write_bytes(&mut comm_p_bytes)?;

    Ok(comm_p_bytes)
}

pub fn piece_inclusion_proofs<AH, BH>(
    piece_specs: &[PieceSpec],
    tree: &HybridMerkleTree<AH, BH>,
) -> Result<Vec<PieceInclusionProof<AH, BH>>>
where
    AH: Hasher,
    BH: Hasher,
{
    piece_specs
        .iter()
        .map(|piece_spec| PieceInclusionProof::new(piece_spec.clone(), tree))
        .collect()
}

impl<AH, BH> PieceInclusionProof<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub fn new(
        piece_spec: PieceSpec,
        tree: &HybridMerkleTree<AH, BH>,
    ) -> Result<PieceInclusionProof<AH, BH>> {
        let PieceSpec {
            comm_p: comm_p_bytes,
            position: first_leaf,
            number_of_leaves: n_piece_leaves,
        } = piece_spec;

        let last_leaf = first_leaf + (n_piece_leaves - 1);
        let subtree_height = piece_spec.height();

        // For now, we only handle aligned pieces.
        if !piece_spec.is_aligned(tree.len()) {
            return Err(Error::UnalignedPiece);
        }

        let first_proof = tree.gen_proof(first_leaf);
        let last_proof = tree.gen_proof(last_leaf);

        let first_proof_path: Vec<&HybridDomain<AH::Domain, BH::Domain>> =
            first_proof.path_with_root().collect();

        let last_proof_path: Vec<&HybridDomain<AH::Domain, BH::Domain>> =
            last_proof.path_with_root().collect();

        // There must be a common root.
        if first_proof_path[subtree_height] != last_proof_path[subtree_height] {
            return Err(Error::MalformedMerkleTree);
        }

        let shared_path: Vec<HybridDomain<AH::Domain, BH::Domain>> = first_proof_path
            [subtree_height..first_proof_path.len() - 1]
            .iter()
            .map(|path_elem| **path_elem)
            .collect();

        let pip = PieceInclusionProof {
            proof_elements: shared_path,
            position: first_leaf,
        };

        let comm_p = {
            let comm_p_beta = BH::Domain::try_from_bytes(&comm_p_bytes)?;
            HybridDomain::Beta(comm_p_beta)
        };

        let is_valid = pip.verify(&tree.root(), &comm_p, n_piece_leaves, tree.n_leaves());

        if is_valid {
            Ok(pip)
        } else {
            Err(Error::BadPieceCommitment)
        }
    }

    // Returns a vector of "is right" bits for the Merkle proof corresponding to `leaf`. The length
    // of the vector is `tree_height` (i.e. there is one bit for each layer in the Merkle tree
    // excluding the last/root layer).
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
    /// `piece_leaves` and `sector_leaves` are in units of `HybridDomain` (i.e. `NODE_SIZE` = 32
    /// bytes).
    pub fn verify(
        &self,
        root: &HybridDomain<AH::Domain, BH::Domain>,
        comm_p: &HybridDomain<AH::Domain, BH::Domain>,
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
        // The need for this check also explains why both `piece_leaves` and `sector_leaves` must
        // be included as public inputs to `verify`.
        if (proof_path.len() != proof_length) || self.proof_elements.len() != proof_length {
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
        root: HybridDomain<AH::Domain, BH::Domain>,
        node: HybridDomain<AH::Domain, BH::Domain>,
        elements: &[HybridDomain<AH::Domain, BH::Domain>],
        is_right_bits: &[bool],
        node_height: usize,
    ) -> bool {
        let calculated_root = (0..is_right_bits.len()).fold(node, |cur, i| {
            let cur_is_right = is_right_bits[i];

            let (left, right) = if cur_is_right {
                (elements[i], cur)
            } else {
                (cur, elements[i])
            };

            let layer_index = node_height + i;

            let child_beta =
                BH::Function::default().node(*left.beta_value(), *right.beta_value(), layer_index);

            HybridDomain::Beta(child_beta)
        });

        println!("\n\nroot => {:?}", root);
        println!("calc'd root => {:?}\n\n", calculated_root);

        root == calculated_root
    }

    /// verify_piece_inclusion_proofs returns true iff each provided piece is proved with respect to root
    /// by the corresponding (by index) proof.
    pub fn verify_all(
        root_bytes: &[u8],
        proofs: &[PieceInclusionProof<AH, BH>],
        comm_ps: &[Fr32Ary],
        n_leaves_per_piece: &[usize],
        n_tree_leaves: usize,
    ) -> Result<bool> {
        // The data layer's tree contains only `HybridDomain::Beta`s.
        let root = {
            let root_beta = BH::Domain::try_from_bytes(root_bytes).unwrap();
            HybridDomain::Beta(root_beta)
        };

        let all_proofs_are_valid = izip!(proofs, comm_ps, n_leaves_per_piece).all(
            |(pip, comm_p_bytes, n_piece_leaves)| {
                let comm_p = {
                    let comm_p_beta = BH::Domain::try_from_bytes(comm_p_bytes).unwrap();
                    HybridDomain::Beta(comm_p_beta)
                };
                pip.verify(&root, &comm_p, *n_piece_leaves, n_tree_leaves)
            },
        );

        Ok(all_proofs_are_valid)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Utility

pub fn piece_is_aligned(position: usize, length: usize, tree_len: usize) -> bool {
    let capacity_at_pos = subtree_capacity(position, tree_len);

    is_pow2(capacity_at_pos) && capacity_at_pos >= length
}

fn height_for_length(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        (n as f64).log2().ceil() as usize
    }
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
    use crate::hasher::hybrid::HybridDomain;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};
    use crate::util::NODE_SIZE;
    use rand::Rng;
    use std::convert::TryInto;

    /// Generate `comm_p` from bytes
    fn generate_piece_commitment<AH, BH>(
        data: &[u8],
    ) -> Result<HybridDomain<AH::Domain, BH::Domain>>
    where
        AH: Hasher,
        BH: Hasher,
    {
        // The data layer's tree contains only `HybridDomain::Beta` nodes.
        let piece_leaves = data
            .chunks(NODE_SIZE)
            .map(|leaf_bytes| BH::Domain::try_from_bytes(leaf_bytes).map(HybridDomain::Beta))
            .collect::<Result<Vec<HybridDomain<AH::Domain, BH::Domain>>>>()?;

        Ok(compute_piece_commitment::<AH, BH>(&piece_leaves))
    }

    /// Generate `comm_p` from bytes and return it as bytes.
    fn generate_piece_commitment_bytes<AH, BH>(data: &[u8]) -> Result<Fr32Ary>
    where
        AH: Hasher,
        BH: Hasher,
    {
        let comm_p = generate_piece_commitment::<AH, BH>(data)?;
        let mut comm_p_bytes: Fr32Ary = [0; NODE_SIZE];

        comm_p.write_bytes(&mut comm_p_bytes)?;

        Ok(comm_p_bytes)
    }

    #[test]
    fn piece_inclusion_proof_pedersen() {
        test_piece_inclusion_proof::<PedersenHasher, PedersenHasher>();
    }

    #[test]
    fn piece_inclusion_proof_sha256() {
        test_piece_inclusion_proof::<Sha256Hasher, Sha256Hasher>();
    }

    #[test]
    fn piece_inclusion_proof_blake2s() {
        test_piece_inclusion_proof::<Blake2sHasher, Blake2sHasher>();
    }

    #[test]
    fn piece_inclusion_proof_pedersen_blake2s() {
        test_piece_inclusion_proof::<PedersenHasher, Blake2sHasher>();
    }

    fn test_piece_inclusion_proof<AH, BH>()
    where
        AH: Hasher,
        BH: Hasher,
    {
        let mut size = NODE_SIZE;

        test_piece_inclusion_proof_aux::<AH, BH>(NODE_SIZE, &[NODE_SIZE], &[0], false);

        //        // Aligned proofs
        while size > 2 {
            for i in 2..size {
                test_piece_inclusion_proof_aux::<AH, BH>(size, &[i], &[0], false);
            }

            size >>= 1;
        }

        //        // Unaligned proof (should fail)
        test_piece_inclusion_proof_aux::<AH, BH>(NODE_SIZE, &[16usize], &[8usize], true);

        //        // Mixed aligned and unaligned
        for i in 0..16 {
            test_piece_inclusion_proof_aux::<AH, BH>(NODE_SIZE, &[8usize], &[i], i % 8 != 0);
        }

        // TODO: when unaligned proofs are supported, test more exhaustively.
    }

    fn test_piece_inclusion_proof_aux<AH, BH>(
        nodes: usize,
        node_lengths: &[usize],
        start_positions: &[usize],
        expect_alignment_error: bool,
    ) where
        AH: Hasher,
        BH: Hasher,
    {
        assert_eq!(node_lengths.len(), 1); // For now.
        let size = nodes * NODE_SIZE;
        let g = BucketGraph::<AH, BH>::new(nodes, 0, 0, new_seed());
        let mut data = vec![0u8; size]; //Vec::<u8>::with_capacity(nodes);

        let data_size = node_lengths[0] * NODE_SIZE;

        for i in 0..data_size {
            data[i] = (((i / NODE_SIZE) + i)
                // Mask out two most significant bits so we will always be Fr32,
                & 63) as u8;
        }

        // The data layer's beta height is always equal to the tree height (i.e.  the tree contains
        // only `HybridDomain::Beta` nodes).
        let beta_height = (nodes as f32).log2().ceil() as usize + 1;
        let tree = g.hybrid_merkle_tree(&data, beta_height).unwrap();

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
            let comm_p = generate_piece_commitment_bytes::<AH, BH>(piece)
                .expect("failed to generate piece commitment");
            comm_ps.push(comm_p);
        }

        let piece_tree = create_piece_tree::<AH, BH>(
            &data
                .chunks(NODE_SIZE)
                .map(|leaf_bytes| {
                    BH::Domain::try_from_bytes(leaf_bytes)
                        .map(HybridDomain::Beta)
                        .unwrap()
                })
                .collect::<Vec<_>>(),
        );
        assert_eq!(tree.leafs(), piece_tree.leafs());

        let mut piece_specs = Vec::new();
        for (&comm_p, (position, number_of_leaves)) in comm_ps.iter().zip(sections.clone()) {
            piece_specs.push(PieceSpec {
                comm_p,
                position,
                number_of_leaves,
            })
        }

        let proofs = piece_inclusion_proofs::<AH, BH>(&piece_specs, &tree);

        if expect_alignment_error {
            assert!(proofs.is_err());
        } else {
            let proofs = proofs.expect("failed to create piece inclusion proofs");
            for (proof, piece_spec) in proofs.iter().zip(piece_specs.clone()) {
                let (_, proof_length) = piece_spec
                    .compute_packing(nodes)
                    .expect("faild to compute packing");
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
                .expect("failed to verify proofs")
            );
        }

        if !expect_alignment_error {
            let proofs = piece_inclusion_proofs::<AH, BH>(&piece_specs, &tree);

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
                wrong_comm_ps.push(
                    generate_piece_commitment_bytes::<AH, BH>(wrong_piece)
                        .expect("failed to generate piece commitment"),
                );
            }

            assert_eq!(
                false,
                PieceInclusionProof::verify_all(
                    &tree.root().into_bytes(),
                    &proofs.expect("failed to generate inclusion proofs"),
                    &wrong_comm_ps,
                    &node_lengths,
                    nodes,
                )
                .expect("failed to verify proofs")
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

    #[test]
    fn test_well_formed_pip_serialization() -> std::result::Result<(), failure::Error> {
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let x = rng.gen_range(0, 1000) as usize;
            let in_bytes: Vec<u8> = (0..(NUM_PIP_HEADER_BYTES + x * NODE_SIZE))
                .map(|_| rand::random::<u8>())
                .collect();
            let piece_inclusion_proof: PieceInclusionProof<PedersenHasher, PedersenHasher> =
                in_bytes.as_slice().try_into()?;
            let out_bytes: Vec<u8> = piece_inclusion_proof.into();

            assert_eq!(in_bytes, out_bytes);
        }

        Ok(())
    }

    #[test]
    fn test_malformed_pip_deserialization() -> std::result::Result<(), failure::Error> {
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let mut x;
            while {
                x = rng.gen_range(0, 1000) as usize;
                x % NODE_SIZE == NUM_PIP_HEADER_BYTES
            } {}

            let in_bytes: Vec<u8> = (0..x).map(|_| rand::random::<u8>()).collect();
            assert!(
                TryInto::<PieceInclusionProof<PedersenHasher, PedersenHasher>>::try_into(
                    in_bytes.as_slice()
                )
                .is_err()
            );
        }

        Ok(())
    }

    #[test]
    fn test_generate_piece_commitment_bytes_from_source() -> Result<()> {
        let some_bytes: Vec<u8> = vec![0; 33];
        let mut some_bytes_slice: &[u8] = &some_bytes;
        assert!(
            generate_piece_commitment_bytes_from_source::<PedersenHasher, PedersenHasher>(
                &mut some_bytes_slice,
            )
            .is_ok(),
            "threshold for sufficient bytes is 32"
        );

        let not_enough_bytes: Vec<u8> = vec![0; 7];
        let mut not_enough_bytes_slice: &[u8] = &not_enough_bytes;
        assert!(
            generate_piece_commitment_bytes_from_source::<PedersenHasher, PedersenHasher>(
                &mut not_enough_bytes_slice,
            )
            .is_err(),
            "insufficient bytes should error out"
        );

        Ok(())
    }
}
