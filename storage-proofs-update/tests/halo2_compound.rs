#![allow(dead_code, unused_imports)]

use std::fs;
use std::path::Path;

use filecoin_hashers::{Domain, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{Unsigned, U0, U2, U4, U8};
use halo2_proofs::pasta::Fp;
use merkletree::{merkle::get_merkle_tree_len, store::StoreConfig};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    halo2::CompoundProof,
    merkle::{create_lc_tree, get_base_tree_count, split_config_and_replica, MerkleTreeTrait},
    proof::ProofScheme,
    util::default_rows_to_discard,
    TEST_SEED,
};
use storage_proofs_update::{
    constants::{
        self, hs, partition_count, validate_tree_r_shape, TreeDArity, SECTOR_SIZE_16_KIB,
        SECTOR_SIZE_1_KIB, SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB,
        SECTOR_SIZE_8_KIB,
    },
    halo2::EmptySectorUpdateCircuit,
    phi, vanilla, EmptySectorUpdate, SetupParams,
};
use tempfile::tempdir;

mod common;

use common::encode_new_replica;

const HS_INDEX: usize = 2;

type TreeD = constants::TreeD<Fp>;
type TreeDDomain = constants::TreeDDomain<Fp>;

type TreeR<U, V, W> = constants::TreeR<Fp, U, V, W>;
type TreeRBase = constants::TreeRBase<Fp>;
type TreeRDomain = constants::TreeRDomain<Fp>;
type TreeRHasher = constants::TreeRHasher<Fp>;

fn test_empty_sector_update_compound<U, V, W, const SECTOR_NODES: usize>()
where
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
    EmptySectorUpdate<Fp, U, V, W>: CompoundProof<
        Fp,
        SECTOR_NODES,
        VanillaSetupParams = SetupParams,
        VanillaPublicInputs = vanilla::PublicInputs<Fp>,
        VanillaPartitionProof = vanilla::PartitionProof<Fp, U, V, W>,
        Circuit = EmptySectorUpdateCircuit<Fp, U, V, W, SECTOR_NODES>,
    >,
{
    validate_tree_r_shape::<U, V, W>(SECTOR_NODES);

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    // Merkle tree storage directory.
    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path();

    // Get TreeR config values.
    let tree_r_base_arity = U::to_usize();
    let tree_r_base_trees = get_base_tree_count::<TreeR<U, V, W>>();
    let tree_r_base_leafs = SECTOR_NODES / tree_r_base_trees;
    let tree_r_base_leafs_bytes = tree_r_base_leafs << 5;
    let tree_r_rows_to_discard = default_rows_to_discard(tree_r_base_leafs, tree_r_base_arity);
    // Total number of nodes in each TreeR base tree.
    let tree_r_base_nodes = get_merkle_tree_len(tree_r_base_leafs, tree_r_base_arity).unwrap();

    // Create random replica-old and write TreeROld.
    let labels_r_old: Vec<TreeRDomain> = (0..SECTOR_NODES)
        .map(|_| TreeRDomain::random(&mut rng))
        .collect();
    // Write old replica-old to disk.
    let replica_old_path = tmp_path.join(Path::new("replica_old"));
    let replica_old: Vec<u8> = labels_r_old.iter().flat_map(Domain::into_bytes).collect();
    fs::write(&replica_old_path, &replica_old).expect("failed to write replica_old to disk");
    // Create TreeROld.
    let tree_r_old_config = StoreConfig {
        path: tmp_path.into(),
        id: "tree-r-old-base".to_string(),
        size: Some(tree_r_base_nodes),
        rows_to_discard: tree_r_rows_to_discard,
    };
    let (tree_r_old_base_configs, replica_old_config) = split_config_and_replica(
        tree_r_old_config.clone(),
        replica_old_path.clone(),
        tree_r_base_leafs,
        tree_r_base_trees,
    )
    .expect("failed to split TreeROld store config");
    // Write each base tree.
    for (base_tree_config, leafs_offset) in tree_r_old_base_configs
        .iter()
        .cloned()
        .zip(replica_old_config.offsets.iter().copied())
    {
        let _base_tree = TreeRBase::from_byte_slice_with_config(
            &replica_old[leafs_offset..leafs_offset + tree_r_base_leafs_bytes],
            base_tree_config,
        )
        .expect("failed to create TreeROld base tree");
    }
    let tree_r_old = create_lc_tree::<TreeR<U, V, W>>(
        tree_r_base_nodes,
        &tree_r_old_base_configs,
        &replica_old_config,
    )
    .expect("failed to create TreeROld");
    let root_r_old = tree_r_old.root();
    let comm_c = TreeRDomain::random(&mut rng);
    let comm_r_old = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &root_r_old);

    // Create random date-new and write TreeDNew.
    let labels_d_new: Vec<TreeDDomain> = (0..SECTOR_NODES)
        .map(|_| TreeDDomain::random(&mut rng))
        .collect();
    let tree_d_arity = TreeDArity::to_usize();
    let tree_d_rows_to_discard = default_rows_to_discard(SECTOR_NODES, tree_d_arity);
    let tree_d_nodes = get_merkle_tree_len(SECTOR_NODES, tree_d_arity).unwrap();
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

    // Encode data-new into replica-new.
    let h = hs(SECTOR_NODES)[HS_INDEX];
    let phi = phi(&comm_d_new, &comm_r_old);
    let labels_r_new = encode_new_replica(&labels_r_old, &labels_d_new, &phi, h);

    // Write new replica-new to disk and create TreeRNew.
    let replica_new_path = tmp_path.join(Path::new("replica_new"));
    let replica_new: Vec<u8> = labels_r_new.iter().flat_map(Domain::into_bytes).collect();
    fs::write(&replica_new_path, &replica_new).expect("failed to write replica_new to disk");
    let tree_r_new_config = StoreConfig {
        path: tmp_path.into(),
        id: "tree-r-new-base".to_string(),
        size: Some(tree_r_base_nodes),
        rows_to_discard: tree_r_rows_to_discard,
    };
    let (tree_r_new_base_configs, replica_new_config) = split_config_and_replica(
        tree_r_new_config.clone(),
        replica_new_path.clone(),
        tree_r_base_leafs,
        tree_r_base_trees,
    )
    .expect("failed to split TreeRNew store config");
    // Write each base tree.
    for (base_tree_config, leafs_offset) in tree_r_new_base_configs
        .iter()
        .cloned()
        .zip(replica_new_config.offsets.iter().copied())
    {
        let _base_tree = TreeRBase::from_byte_slice_with_config(
            &replica_new[leafs_offset..leafs_offset + tree_r_base_leafs_bytes],
            base_tree_config,
        )
        .expect("failed to create base-tree");
    }
    let tree_r_new = create_lc_tree::<TreeR<U, V, W>>(
        tree_r_base_nodes,
        &tree_r_new_base_configs,
        &replica_new_config,
    )
    .expect("failed to create TreeRNew");
    let root_r_new = tree_r_new.root();
    let comm_r_new = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &root_r_new);

    let vanilla_pub_inputs = vanilla::PublicInputs::<Fp> {
        // This `k` value will be incremented when proving all partitions.
        k: 0,
        comm_r_old,
        comm_d_new,
        comm_r_new,
        h,
    };

    let vanilla_priv_inputs = vanilla::PrivateInputs::<Fp> {
        comm_c,
        tree_r_old_config,
        old_replica_path: replica_old_path,
        tree_d_new_config,
        tree_r_new_config,
        replica_path: replica_new_path,
    };

    let vanilla_setup_params = SetupParams {
        sector_bytes: (SECTOR_NODES << 5) as u64,
    };

    let vanilla_pub_params =
        EmptySectorUpdate::<Fp, U, V, W>::setup(&vanilla_setup_params).unwrap();

    let partition_count = partition_count(SECTOR_NODES);
    let vanilla_partition_proofs = EmptySectorUpdate::<Fp, U, V, W>::prove_all_partitions(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_priv_inputs,
        partition_count,
    )
    .expect("failed to generate vanilla partition proofs");
    assert_eq!(vanilla_partition_proofs.len(), partition_count);

    let keypair = {
        let circ = EmptySectorUpdateCircuit::blank_circuit();
        EmptySectorUpdate::create_keypair(&circ).expect("failed to create halo2 keypair")
    };

    let circ_partition_proofs = EmptySectorUpdate::prove_all_partitions_with_vanilla(
        &vanilla_setup_params,
        &vanilla_pub_inputs,
        &vanilla_partition_proofs,
        &keypair,
    )
    .expect("failed to generate halo2 circuit proofs from vanilla partition proofs");

    <EmptySectorUpdate<Fp, U, V, W> as CompoundProof<Fp, SECTOR_NODES>>::verify_all_partitions(
        &vanilla_setup_params,
        &vanilla_pub_inputs,
        &circ_partition_proofs,
        &keypair,
    )
    .expect("failed to verify halo2 circuit partition proofs");
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_compound_1kib_halo2() {
    test_empty_sector_update_compound::<U8, U4, U0, SECTOR_SIZE_1_KIB>();
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_compound_2kib_halo2() {
    test_empty_sector_update_compound::<U8, U0, U0, SECTOR_SIZE_2_KIB>();
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_compound_4kib_halo2() {
    test_empty_sector_update_compound::<U8, U2, U0, SECTOR_SIZE_4_KIB>();
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_compound_8kib_halo2() {
    test_empty_sector_update_compound::<U8, U4, U0, SECTOR_SIZE_8_KIB>();
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_compound_16kib_halo2() {
    test_empty_sector_update_compound::<U8, U8, U0, SECTOR_SIZE_16_KIB>();
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_compound_32kib_halo2() {
    test_empty_sector_update_compound::<U8, U8, U2, SECTOR_SIZE_32_KIB>();
}
