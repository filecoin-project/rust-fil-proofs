use std::path::Path;

use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher};
use generic_array::typenum::Unsigned;
use merkletree::store::StoreConfig;

use storage_proofs_core::{
    merkle::{MerkleTreeTrait, MerkleTreeWrapper},
    util::default_rows_to_discard,
};
use storage_proofs_update::{constants::TreeRDomain, rho};

// Selects a value for `h` via `h = hs[log2(h_select)]`; default to taking `h = hs[2]`.
#[allow(dead_code)]
pub const H_SELECT: u64 = 1 << 2;

#[allow(dead_code)]
pub fn create_tree<Tree: MerkleTreeTrait>(
    labels: &[<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain],
    tmp_path: &Path,
    tree_name: &str,
) -> MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>
{
    let sector_nodes = labels.len();
    let base_arity = Tree::Arity::to_usize();
    let sub_arity = Tree::SubTreeArity::to_usize();
    let top_arity = Tree::TopTreeArity::to_usize();

    // Create a single base-tree, a single sub-tree (out of base-trees), or a single top-tree
    // (out of sub-trees, each made of base-trees).
    if sub_arity == 0 && top_arity == 0 {
        let config = StoreConfig::new(
            tmp_path,
            tree_name.to_string(),
            default_rows_to_discard(sector_nodes, base_arity),
        );
        let leafs = labels.iter().copied().map(Ok);
        MerkleTreeWrapper::try_from_iter_with_config(leafs, config)
            .unwrap_or_else(|_| panic!("failed to create non-compound-tree {}", tree_name))
    } else if top_arity == 0 {
        let base_tree_count = sub_arity;
        let leafs_per_base_tree = sector_nodes / base_tree_count;
        let rows_to_discard = default_rows_to_discard(leafs_per_base_tree, base_arity);
        let base_trees: Vec<MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity>> = (0
            ..base_tree_count)
            .map(|i| {
                let config = StoreConfig::new(
                    tmp_path,
                    format!("{}-base-{}", tree_name, i),
                    rows_to_discard,
                );
                let leafs = labels[i * leafs_per_base_tree..(i + 1) * leafs_per_base_tree]
                    .iter()
                    .copied()
                    .map(Ok);
                MerkleTreeWrapper::try_from_iter_with_config(leafs, config)
                    .unwrap_or_else(|_| panic!("failed to create {} base-tree {}", tree_name, i))
            })
            .collect();
        MerkleTreeWrapper::from_trees(base_trees)
            .unwrap_or_else(|_| panic!("failed to create {} from base-trees", tree_name))
    } else {
        let base_tree_count = top_arity * sub_arity;
        let sub_tree_count = top_arity;
        let leafs_per_base_tree = sector_nodes / base_tree_count;
        let base_trees_per_sub_tree = sub_arity;
        let rows_to_discard = default_rows_to_discard(leafs_per_base_tree, base_arity);
        let sub_trees: Vec<
            MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity, Tree::SubTreeArity>,
        > = (0..sub_tree_count)
            .map(|sub_index| {
                let first_sub_leaf = sub_index * base_trees_per_sub_tree * leafs_per_base_tree;
                let base_trees: Vec<MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity>> = (0
                    ..base_trees_per_sub_tree)
                    .map(|base_index| {
                        let config = StoreConfig::new(
                            tmp_path,
                            format!("{}-sub-{}-base-{}", tree_name, sub_index, base_index),
                            rows_to_discard,
                        );
                        let first_base_leaf = first_sub_leaf + base_index * leafs_per_base_tree;
                        let leafs = labels[first_base_leaf..first_base_leaf + leafs_per_base_tree]
                            .iter()
                            .copied()
                            .map(Ok);
                        MerkleTreeWrapper::try_from_iter_with_config(leafs, config).unwrap_or_else(
                            |_| {
                                panic!(
                                    "failed to create {} sub-tree {} base-tree {}",
                                    tree_name, sub_index, base_index,
                                )
                            },
                        )
                    })
                    .collect();
                MerkleTreeWrapper::from_trees(base_trees).unwrap_or_else(|_| {
                    panic!(
                        "failed to create {} sub-tree {} from base-trees",
                        tree_name, sub_index,
                    )
                })
            })
            .collect();
        MerkleTreeWrapper::from_sub_trees(sub_trees)
            .unwrap_or_else(|_| panic!("failed to create {} from sub-trees", tree_name))
    }
}

pub fn encode_new_replica<TreeD: Domain>(
    labels_r_old: &[TreeRDomain],
    labels_d_new: &[TreeD],
    phi: &TreeRDomain,
    h: usize,
) -> Vec<TreeRDomain> {
    let sector_nodes = labels_r_old.len();
    assert_eq!(sector_nodes, labels_d_new.len());

    // Right-shift each node-index by `get_high_bits_shr` to get its `h` high bits.
    let node_index_bit_len = sector_nodes.trailing_zeros() as usize;
    let get_high_bits_shr = node_index_bit_len - h;

    (0..sector_nodes)
        .map(|node| {
            // Take the `h` high bits from the node-index and compute this node's compute `rho`.
            let high = (node >> get_high_bits_shr) as u32;
            let rho = rho(phi, high);

            // `label_r_new = label_r_old + label_d_new * rho`
            let label_r_old: Fr = labels_r_old[node].into();
            let label_d_new: Fr = labels_d_new[node].into();
            (label_r_old + label_d_new * rho).into()
        })
        .collect()
}
