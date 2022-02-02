#![allow(dead_code)]

use std::fs;
use std::path::Path;

use ff::PrimeField;
use filecoin_hashers::{Domain, Hasher, PoseidonArity};
use generic_array::typenum::Unsigned;
use merkletree::{merkle::get_merkle_tree_len, store::StoreConfig};
use storage_proofs_core::merkle::{create_lc_tree, get_base_tree_count, split_config_and_replica};
use storage_proofs_update::{
    constants::{
        TreeD, TreeDArity, TreeDDomain, TreeDHasher, TreeR, TreeRBase, TreeRDomain, TreeRHasher,
    },
    rho,
};

// Selects a value for `h` via `h = hs[log2(h_select)]`; default tests to use `h = hs[3]`.
pub const H_SELECT: u64 = 1 << 3;

// EmptySectorUpdate (non-Poseidon).
pub fn create_tree_d_new<F>(labels_d_new: &[TreeDDomain<F>], tmp_dir: &Path) -> TreeD<F>
where
    F: PrimeField,
    TreeDHasher<F>: Hasher<Domain = TreeDDomain<F>>,
{
    let num_leafs = labels_d_new.len();
    let arity = TreeDArity::to_usize();
    let num_nodes = get_merkle_tree_len(num_leafs, arity).unwrap();
    let config = StoreConfig {
        path: tmp_dir.into(),
        id: "tree-d-new".to_string(),
        size: Some(num_nodes),
        rows_to_discard: 0,
    };
    TreeD::try_from_iter_with_config(labels_d_new.iter().copied().map(Ok), config)
        .expect("failed to create tree-d-new")
}

// EmptySectorUpdate-Poseidon.
#[inline]
pub fn create_tree_d_new_poseidon<F, U, V, W>(
    labels_d_new: &[TreeRDomain<F>],
    tmp_dir: &Path,
) -> TreeR<F, U, V, W>
where
    F: PrimeField,
    TreeRHasher<F>: Hasher<Domain = TreeRDomain<F>>,
    TreeRDomain<F>: Domain<Field = F>,
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    create_tree_r(labels_d_new, tmp_dir, "tree-d-new", "data_new")
}

#[inline]
pub fn create_tree_r_old<F, U, V, W>(
    replica_old: &[TreeRDomain<F>],
    tmp_dir: &Path,
) -> TreeR<F, U, V, W>
where
    F: PrimeField,
    TreeRHasher<F>: Hasher<Domain = TreeRDomain<F>>,
    TreeRDomain<F>: Domain<Field = F>,
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    create_tree_r(replica_old, tmp_dir, "tree-r-old", "replica_old")
}

#[inline]
pub fn create_tree_r_new<F, U, V, W>(
    replica_new: &[TreeRDomain<F>],
    tmp_dir: &Path,
) -> TreeR<F, U, V, W>
where
    F: PrimeField,
    TreeRHasher<F>: Hasher<Domain = TreeRDomain<F>>,
    TreeRDomain<F>: Domain<Field = F>,
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    create_tree_r(replica_new, tmp_dir, "tree-r-new", "replica_new")
}

fn create_tree_r<F, U, V, W>(
    replica: &[TreeRDomain<F>],
    tmp_dir: &Path,
    tree_name: &str,
    replica_name: &str,
) -> TreeR<F, U, V, W>
where
    F: PrimeField,
    TreeRHasher<F>: Hasher<Domain = TreeRDomain<F>>,
    TreeRDomain<F>: Domain<Field = F>,
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    let base_arity = U::to_usize();

    let sector_nodes = replica.len();
    let base_tree_count = get_base_tree_count::<TreeR<F, U, V, W>>();
    let leafs_per_base_tree = sector_nodes / base_tree_count;
    let base_tree_leafs_bytes = leafs_per_base_tree << 5;
    // Total number of nodes (across all tree layers) per base-tree.
    let nodes_per_base_tree = get_merkle_tree_len(leafs_per_base_tree, base_arity).unwrap();

    // Write replica to disk.
    let replica_path = tmp_dir.join(Path::new(replica_name));
    let replica_bytes: Vec<u8> = replica.iter().flat_map(Domain::into_bytes).collect();
    fs::write(&replica_path, &replica_bytes).expect("failed to write replica to disk");

    // Get base-tree configs.
    let config = StoreConfig {
        path: tmp_dir.into(),
        id: format!("{}-base", tree_name),
        size: Some(nodes_per_base_tree),
        rows_to_discard: 0,
    };
    let (base_tree_configs, replica_config) =
        split_config_and_replica(config, replica_path, leafs_per_base_tree, base_tree_count)
            .expect("failed to split store config");
    assert_eq!(base_tree_configs.len(), base_tree_count);

    // Write each base tree.
    for (base_tree_config, leafs_offset) in base_tree_configs
        .iter()
        .zip(replica_config.offsets.iter().copied())
    {
        let leafs = &replica_bytes[leafs_offset..leafs_offset + base_tree_leafs_bytes];
        let _base_tree = TreeRBase::from_byte_slice_with_config(leafs, base_tree_config.clone())
            .expect("failed to create base-tree");
    }

    create_lc_tree::<TreeR<F, U, V, W>>(nodes_per_base_tree, &base_tree_configs, &replica_config)
        .expect("failed to create LCTree")
}

pub fn encode_new_replica<D>(
    labels_r_old: &[TreeRDomain<D::Field>],
    labels_d_new: &[D],
    phi: &TreeRDomain<D::Field>,
    h: usize,
) -> Vec<TreeRDomain<D::Field>>
where
    // TreeD domain.
    D: Domain,
    // TreeD and TreeR Domains must use the same field.
    TreeRDomain<D::Field>: Domain<Field = D::Field>,
{
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
            let label_r_old: D::Field = labels_r_old[node].into();
            let label_d_new: D::Field = labels_d_new[node].into();
            (label_r_old + label_d_new * rho).into()
        })
        .collect()
}
