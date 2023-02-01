#![cfg(feature = "halo2")]
#![allow(unused_imports, dead_code)]

use ff::{Field, PrimeField};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher, PoseidonArity};
use generic_array::typenum::{U0, U2, U4, U8};
use halo2_proofs::pasta::Fp;
use merkletree::store::StoreConfig;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion, cache_key::CacheKey, halo2::CompoundProof, merkle::DiskTree,
    proof::ProofScheme, test_helper::setup_replica, util::default_rows_to_discard,
    SECTOR_NODES_16_KIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB,
    SECTOR_NODES_8_KIB, TEST_SEED,
};
use storage_proofs_porep::{
    stacked::{
        self as vanilla,
        halo2::{
            constants::{challenge_count, num_layers, partition_count, DRG_PARENTS, EXP_PARENTS},
            SdrPorepCircuit,
        },
        LayerChallenges, SetupParams, StackedDrg, TemporaryAux, TemporaryAuxCache, BINARY_ARITY,
    },
    PoRep,
};
use tempfile::tempdir;

type TreeDHasher = Sha256Hasher<Fp>;
type TreeDDomain = <TreeDHasher as Hasher>::Domain;
type TreeRHasher = PoseidonHasher<Fp>;
type TreeRDomain = <TreeRHasher as Hasher>::Domain;
type TreeR<U, V, W> = DiskTree<TreeRHasher, U, V, W>;

fn test_sdr_porep_compound<'a, U, V, W, const SECTOR_NODES: usize>()
where
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
    StackedDrg<'a, TreeR<U, V, W>, TreeDHasher>: CompoundProof<
        Fp,
        SECTOR_NODES,
        VanillaSetupParams = SetupParams,
        VanillaPublicInputs = vanilla::PublicInputs<TreeRDomain, TreeDDomain>,
        VanillaPartitionProof = Vec<vanilla::Proof<TreeR<U, V, W>, TreeDHasher>>,
        Circuit = SdrPorepCircuit<Fp, U, V, W, SECTOR_NODES>,
    >,
{
    let sector_bytes = SECTOR_NODES << 5;
    let num_layers = num_layers(SECTOR_NODES);
    let challenge_count = challenge_count(SECTOR_NODES);
    let layer_challenges = LayerChallenges::new(num_layers, challenge_count);
    let partition_count = partition_count(SECTOR_NODES);

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let replica_id = Fp::random(&mut rng);

    let mut data = Vec::<u8>::with_capacity(sector_bytes);
    for _ in 0..SECTOR_NODES {
        data.extend_from_slice(Fp::random(&mut rng).to_repr().as_ref());
    }

    let cache_dir = tempdir().unwrap();

    // TreeD config.
    let config = StoreConfig::new(
        cache_dir.path(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(SECTOR_NODES, BINARY_ARITY),
    );

    // Create replica.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let vanilla_setup_params = SetupParams {
        nodes: SECTOR_NODES,
        degree: DRG_PARENTS,
        expansion_degree: EXP_PARENTS,
        porep_id: [44; 32],
        layer_challenges,
        api_version: ApiVersion::V1_1_0,
    };

    let vanilla_pub_params =
        StackedDrg::<TreeR<U, V, W>, TreeDHasher>::setup(&vanilla_setup_params).unwrap();

    let (tau, (p_aux, t_aux)) = StackedDrg::<TreeR<U, V, W>, TreeDHasher>::replicate(
        &vanilla_pub_params,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        None,
        config,
        replica_path.clone(),
    )
    .expect("replication failed");

    // Store copy of original t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all elements based on the
    // configs stored in TemporaryAux.
    let t_aux =
        TemporaryAuxCache::new(&t_aux, replica_path).expect("failed to restore contents of t_aux");

    let vanilla_pub_inputs = vanilla::PublicInputs {
        replica_id: replica_id.into(),
        seed: rng.gen(),
        tau: Some(tau),
        k: None,
    };

    let vanilla_priv_inputs = vanilla::PrivateInputs { p_aux, t_aux };

    let vanilla_partition_proofs = StackedDrg::prove_all_partitions(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_priv_inputs,
        partition_count,
    )
    .expect("failed to generate vanilla_partition proofs");
    assert_eq!(vanilla_partition_proofs.len(), partition_count);

    let vanilla_proofs_are_valid = <StackedDrg<_, _> as ProofScheme<'_>>::verify_all_partitions(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_partition_proofs,
    )
    .expect("failed to verify vanilla partition proofs");
    assert!(vanilla_proofs_are_valid);

    // Discard cached MTs that are no longer needed.
    TemporaryAux::clear_temp(t_aux_orig).expect("t_aux delete failed");

    let keypair = {
        let circ = SdrPorepCircuit::blank_circuit();
        StackedDrg::create_keypair(&circ)
            .expect("failed to create halo2 keypair for sdr-porep circuit")
    };

    let circ_partition_proofs = StackedDrg::prove_all_partitions_with_vanilla(
        &vanilla_setup_params,
        &vanilla_pub_inputs,
        &vanilla_partition_proofs,
        &keypair,
    )
    .expect("failed to generate halo2 circuit proofs from vanilla partition proofs");

    <StackedDrg<_, _> as CompoundProof<_, SECTOR_NODES>>::verify_all_partitions(
        &vanilla_setup_params,
        &vanilla_pub_inputs,
        &circ_partition_proofs,
        &keypair,
    )
    .expect("failed to verify halo2 circuit partition proofs");

    cache_dir.close().expect("Failed to remove cache dir");
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_compound_2kib_halo2() {
    test_sdr_porep_compound::<U8, U0, U0, SECTOR_NODES_2_KIB>();
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_compound_4kib_halo2() {
    test_sdr_porep_compound::<U8, U2, U0, SECTOR_NODES_4_KIB>();
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_compound_8kib_halo2() {
    test_sdr_porep_compound::<U8, U4, U0, SECTOR_NODES_8_KIB>();
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_compound_16kib_halo2() {
    test_sdr_porep_compound::<U8, U8, U0, SECTOR_NODES_16_KIB>();
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_compound_32kib_halo2() {
    test_sdr_porep_compound::<U8, U8, U2, SECTOR_NODES_32_KIB>();
}
