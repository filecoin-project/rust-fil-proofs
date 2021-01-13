use filecoin_proofs::{
    with_shape, SECTOR_SIZE_16_MIB, SECTOR_SIZE_1_GIB, SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_GIB,
    SECTOR_SIZE_4_KIB, SECTOR_SIZE_512_MIB, SECTOR_SIZE_64_GIB, SECTOR_SIZE_8_MIB,
};
use generic_array::typenum::Unsigned;
use storage_proofs_core::merkle::MerkleTreeTrait;

fn canonical_shape(sector_size: u64) -> (usize, usize, usize) {
    // This could perhaps be cleaned up, but I think it expresses the intended constraints
    // and is consistent with our current hard-coded size->shape mappings.
    assert_eq!(sector_size.count_ones(), 1);
    let log_byte_size = sector_size.trailing_zeros();
    let log_nodes = log_byte_size - 5; // 2^5 = 32-byte nodes

    let max_tree_log = 3; // Largest allowable arity. The optimal shape.

    let log_max_base = 27; // 4 GiB worth of nodes
    let log_base = max_tree_log; // Base must be oct trees.x
    let log_in_base = u32::min(log_max_base, (log_nodes / log_base) * log_base); // How many nodes in base?

    let log_upper = log_nodes - log_in_base; // Nodes in sub and upper combined.
    let log_rem = log_upper % max_tree_log; // Remainder after filling optimal trees.

    let (log_sub, log_top) = {
        // Are the upper trees empty?
        if log_upper > 0 {
            // Do we need a remainder tree?
            if log_rem == 0 {
                (Some(max_tree_log), None) // No remainder tree, fill the sub tree optimall.y
            } else {
                // Need a remainder tree.

                // Do we have room for another max tree?
                if log_upper > max_tree_log {
                    // There is room. Use the sub tree for as much overflow as we can fit optimally.
                    // And put the rest in the top tree.
                    (Some(max_tree_log), Some(log_rem))
                } else {
                    // Can't fit another max tree.
                    // Just put the remainder in the sub tree.
                    (Some(log_rem), None)
                }
            }
        } else {
            // Upper trees are empty.
            (None, None)
        }
    };

    let base = 1 << log_base;
    let sub = if let Some(l) = log_sub { 1 << l } else { 0 };
    let top = if let Some(l) = log_top { 1 << l } else { 0 };

    (base, sub, top)
}

fn arities_to_usize<Tree: MerkleTreeTrait>() -> (usize, usize, usize) {
    (
        Tree::Arity::to_usize(),
        Tree::SubTreeArity::to_usize(),
        Tree::TopTreeArity::to_usize(),
    )
}

#[test]
fn test_with_shape_macro() {
    test_with_shape_macro_aux(SECTOR_SIZE_2_KIB);
    test_with_shape_macro_aux(SECTOR_SIZE_4_KIB);
    test_with_shape_macro_aux(SECTOR_SIZE_8_MIB);
    test_with_shape_macro_aux(SECTOR_SIZE_16_MIB);
    test_with_shape_macro_aux(SECTOR_SIZE_512_MIB);
    test_with_shape_macro_aux(SECTOR_SIZE_1_GIB);
    test_with_shape_macro_aux(SECTOR_SIZE_32_GIB);
    test_with_shape_macro_aux(SECTOR_SIZE_64_GIB);
}

fn test_with_shape_macro_aux(sector_size: u64) {
    let expected = canonical_shape(sector_size);
    let arities = with_shape!(sector_size, arities_to_usize);
    assert_eq!(
        arities, expected,
        "Wrong shape for sector size {}: have {:?} but need {:?}.",
        sector_size, arities, expected
    );
}
