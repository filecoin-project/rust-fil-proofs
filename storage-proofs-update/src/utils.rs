use generic_array::typenum::Unsigned;
use storage_proofs_core::merkle::MerkleTreeTrait;

pub fn validate_tree_shape<Tree: MerkleTreeTrait>(sector_nodes: usize) {
    let base_arity = Tree::Arity::to_usize();
    let sub_arity = Tree::SubTreeArity::to_usize();
    let top_arity = Tree::TopTreeArity::to_usize();

    assert!([base_arity, sub_arity, top_arity]
        .iter()
        .all(|a| [0, 2, 4, 8].contains(a)));
    assert!(base_arity > 0);

    let mut nodes_remaining = sector_nodes as f32;
    if top_arity > 0 {
        assert!(sub_arity > 0);
        nodes_remaining /= top_arity as f32;
        assert_eq!(nodes_remaining.fract(), 0.0);
    }
    if sub_arity > 0 {
        nodes_remaining /= sub_arity as f32;
        assert_eq!(nodes_remaining.fract(), 0.0);
    }
    let base_path_len = nodes_remaining.log(base_arity as f32);
    assert_eq!(base_path_len.fract(), 0.0)
}
