use std::fs;
use std::path::Path;

use filecoin_hashers::{Domain, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{Unsigned, U0, U2, U4, U8};
use merkletree::{merkle::get_merkle_tree_len, store::StoreConfig};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    merkle::{
        create_lc_tree, get_base_tree_count, split_config_and_replica, LCTree, MerkleTreeTrait,
    },
    util::default_rows_to_discard,
    TEST_SEED,
};
use storage_proofs_update::{
    constants::{
        hs, partition_count, validate_tree_r_shape, TreeD, TreeDArity, TreeDDomain, TreeRBaseTree,
        TreeRDomain, TreeRHasher, SECTOR_SIZE_16_KIB, SECTOR_SIZE_1_KIB, SECTOR_SIZE_2_KIB,
        SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB, SECTOR_SIZE_8_KIB,
    },
    phi, EmptySectorUpdateCompound, PrivateInputs, PublicInputs, SetupParams,
};
use tempfile::tempdir;

mod common;

const HS_INDEX: usize = 2;

type TreeR<U, V, W> = LCTree<TreeRHasher, U, V, W>;

fn test_empty_sector_update_compound<U, V, W>(sector_nodes: usize)
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    validate_tree_r_shape::<TreeR<U, V, W>>(sector_nodes);

    let base_arity = U::to_usize();

    let tree_r_base_tree_count = get_base_tree_count::<TreeR<U, V, W>>();
    let tree_r_leafs_per_base_tree = sector_nodes / tree_r_base_tree_count;
    let tree_r_base_tree_leafs_byte_len = tree_r_leafs_per_base_tree << 5;
    let tree_r_rows_to_discard = default_rows_to_discard(tree_r_leafs_per_base_tree, base_arity);
    // Total number of nodes in each base-tree of TreeR.
    let tree_r_base_tree_nodes =
        get_merkle_tree_len(tree_r_leafs_per_base_tree, base_arity).unwrap();

    let h = hs(sector_nodes)[HS_INDEX];

    let mut rng = XorShiftRng::from_seed(TEST_SEED);
    let comm_c = TreeRDomain::random(&mut rng);

    // Merkle tree storage directory.
    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path();

    // Create random old replica.
    let labels_r_old: Vec<TreeRDomain> = (0..sector_nodes)
        .map(|_| TreeRDomain::random(&mut rng))
        .collect();
    // Write old replica to disk.
    let replica_old_path = tmp_path.join(Path::new("replica_old"));
    let replica_old: Vec<u8> = labels_r_old
        .iter()
        .flat_map(|label| label.into_bytes())
        .collect();
    fs::write(&replica_old_path, &replica_old).expect("failed to write replica_old to disk");
    // Create TreeROld.
    let tree_r_old_config = StoreConfig {
        path: tmp_path.into(),
        id: "tree-r-old-base".to_string(),
        size: Some(tree_r_base_tree_nodes),
        rows_to_discard: tree_r_rows_to_discard,
    };
    let (tree_r_old_configs, replica_old_config) = split_config_and_replica(
        tree_r_old_config.clone(),
        replica_old_path.clone(),
        tree_r_leafs_per_base_tree,
        tree_r_base_tree_count,
    )
    .expect("failed to split store config");
    assert_eq!(tree_r_old_configs.len(), tree_r_base_tree_count);
    // Write each base tree.
    for (base_tree_config, leafs_offset) in tree_r_old_configs
        .iter()
        .zip(replica_old_config.offsets.iter().copied())
    {
        let leafs = &replica_old[leafs_offset..leafs_offset + tree_r_base_tree_leafs_byte_len];
        let _base_tree =
            TreeRBaseTree::from_byte_slice_with_config(leafs, base_tree_config.clone())
                .expect("failed to create base-tree");
    }
    let tree_r_old = create_lc_tree::<TreeR<U, V, W>>(
        tree_r_base_tree_nodes,
        &tree_r_old_configs,
        &replica_old_config,
    )
    .expect("failed to create TreeROld");
    let root_r_old = tree_r_old.root();
    let comm_r_old = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &root_r_old);

    // Create random TreeDNew.
    let labels_d_new: Vec<TreeDDomain> = (0..sector_nodes)
        .map(|_| TreeDDomain::random(&mut rng))
        .collect();
    let tree_d_rows_to_discard = default_rows_to_discard(sector_nodes, TreeDArity::to_usize());
    let tree_d_nodes = get_merkle_tree_len(sector_nodes, TreeDArity::to_usize()).unwrap();
    let tree_d_new_config = StoreConfig {
        path: tmp_path.into(),
        id: "tree-d-new".to_string(),
        size: Some(tree_d_nodes),
        rows_to_discard: tree_d_rows_to_discard,
    };
    let tree_d_new = TreeD::try_from_iter_with_config(
        labels_d_new.iter().copied().map(Ok),
        tree_d_new_config.clone(),
    )
    .expect("failed to create TreeDNew");
    let comm_d_new = tree_d_new.root();

    // Encode `labels_d_new` into `labels_r_new`.
    let phi = phi(&comm_d_new, &comm_r_old);
    let labels_r_new = common::encode_new_replica(&labels_r_old, &labels_d_new, &phi, h);
    // Write new replica to disk.
    let replica_new_path = tmp_path.join(Path::new("replica_new"));
    let replica_new: Vec<u8> = labels_r_new
        .iter()
        .flat_map(|label| label.into_bytes())
        .collect();
    fs::write(&replica_new_path, &replica_new).expect("failed to write replica_new to disk");
    // Create TreeRNew.
    let tree_r_new_config = StoreConfig {
        path: tmp_path.into(),
        id: "tree-r-new-base".to_string(),
        size: Some(tree_r_base_tree_nodes),
        rows_to_discard: tree_r_rows_to_discard,
    };
    let (tree_r_new_configs, replica_new_config) = split_config_and_replica(
        tree_r_new_config.clone(),
        replica_new_path.clone(),
        tree_r_leafs_per_base_tree,
        tree_r_base_tree_count,
    )
    .expect("failed to split store config");
    assert_eq!(tree_r_new_configs.len(), tree_r_base_tree_count);
    // Write each base tree.
    for (base_tree_config, leafs_offset) in tree_r_new_configs
        .iter()
        .zip(replica_new_config.offsets.iter().copied())
    {
        let leafs = &replica_new[leafs_offset..leafs_offset + tree_r_base_tree_leafs_byte_len];
        let _base_tree =
            TreeRBaseTree::from_byte_slice_with_config(leafs, base_tree_config.clone())
                .expect("failed to create base-tree");
    }
    let tree_r_new = create_lc_tree::<TreeR<U, V, W>>(
        tree_r_base_tree_nodes,
        &tree_r_new_configs,
        &replica_new_config,
    )
    .expect("failed to create TreeRNew");
    let root_r_new = tree_r_new.root();
    let comm_r_new = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &root_r_new);

    // Setup compound-proof.
    let sector_bytes = (sector_nodes as u64) << 5;
    let partition_count = partition_count(sector_nodes);
    let setup_params_compound = compound_proof::SetupParams {
        vanilla_params: SetupParams { sector_bytes },
        partitions: Some(partition_count),
        priority: true,
    };
    let pub_params_compound =
        EmptySectorUpdateCompound::<TreeR<U, V, W>>::setup(&setup_params_compound).unwrap();

    // Prove generate vanilla and circuit proofs for all partitions.
    let pub_inputs = PublicInputs {
        // This `k` value is ignored when proving all partitions; each partition's `k` public-input
        // is set by `EmptySectorUpdateCompound`.
        k: 0,
        comm_r_old,
        comm_d_new,
        comm_r_new,
        h,
    };

    let priv_inputs = PrivateInputs {
        comm_c,
        tree_r_old_config,
        old_replica_path: replica_old_path,
        tree_d_new_config,
        tree_r_new_config,
        replica_path: replica_new_path,
    };

    let blank_groth_params = EmptySectorUpdateCompound::<TreeR<U, V, W>>::groth_params(
        Some(&mut rng),
        &pub_params_compound.vanilla_params,
    )
    .expect("failed to generate groth params");

    let multi_proof = EmptySectorUpdateCompound::<TreeR<U, V, W>>::prove(
        &pub_params_compound,
        &pub_inputs,
        &priv_inputs,
        &blank_groth_params,
    )
    .expect("failed while proving");

    let is_valid = EmptySectorUpdateCompound::<TreeR<U, V, W>>::verify(
        &pub_params_compound,
        &pub_inputs,
        &multi_proof,
        &(),
    )
    .expect("failed while verifying");

    assert!(is_valid);
}

#[test]
fn test_empty_sector_update_compound_1kib() {
    test_empty_sector_update_compound::<U8, U4, U0>(SECTOR_SIZE_1_KIB);
}

#[test]
fn test_empty_sector_update_compound_2kib() {
    test_empty_sector_update_compound::<U8, U0, U0>(SECTOR_SIZE_2_KIB);
}

#[test]
fn test_empty_sector_update_compound_4kib() {
    test_empty_sector_update_compound::<U8, U2, U0>(SECTOR_SIZE_4_KIB);
}

#[test]
fn test_empty_sector_update_compound_8kib() {
    test_empty_sector_update_compound::<U8, U4, U0>(SECTOR_SIZE_8_KIB);
}

#[test]
fn test_empty_sector_update_compound_16kib() {
    test_empty_sector_update_compound::<U8, U8, U0>(SECTOR_SIZE_16_KIB);
}

#[test]
fn test_empty_sector_update_compound_32kib() {
    test_empty_sector_update_compound::<U8, U8, U2>(SECTOR_SIZE_32_KIB);
}
