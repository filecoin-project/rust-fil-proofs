use filecoin_hashers::{
    poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, Hasher, PoseidonArity,
};
use generic_array::typenum::{U0, U2, U4, U8};
use halo2_proofs::{arithmetic::FieldExt, dev::MockProver, pasta::Fp};
use merkletree::store::StoreConfig;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion, cache_key::CacheKey, merkle::DiskTree, proof::ProofScheme,
    test_helper::setup_replica, util::default_rows_to_discard, TEST_SEED,
};
use storage_proofs_porep::{
    stacked::{
        self as vanilla,
        halo2::{
            circuit::{self, SdrPorepCircuit},
            constants::{
                challenge_count, num_layers, partition_count, DRG_PARENTS, EXP_PARENTS,
                SECTOR_NODES_16_KIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB,
                SECTOR_NODES_8_KIB,
            },
        },
        LayerChallenges, SetupParams, StackedDrg, TemporaryAux, TemporaryAuxCache, BINARY_ARITY,
    },
    PoRep,
};
use tempfile::tempdir;

type TreeR<F, U, V, W> = DiskTree<PoseidonHasher<F>, U, V, W>;

fn test_sdr_porep_circuit<F, U, V, W, const SECTOR_NODES: usize>()
where
    F: FieldExt,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    Sha256Hasher<F>: Hasher,
    <Sha256Hasher<F> as Hasher>::Domain: Domain<Field = F>,
    PoseidonHasher<F>: Hasher,
    <PoseidonHasher<F> as Hasher>::Domain: Domain<Field = F>,
{
    let sector_bytes = SECTOR_NODES << 5;
    let num_layers = num_layers::<SECTOR_NODES>();
    let challenge_count = challenge_count::<SECTOR_NODES>();
    let layer_challenges = LayerChallenges::new(num_layers, challenge_count);
    let partition_count = partition_count::<SECTOR_NODES>();
    let k = 0;

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let replica_id = F::random(&mut rng);

    let mut data = Vec::<u8>::with_capacity(sector_bytes);
    for _ in 0..SECTOR_NODES {
        data.extend_from_slice(F::random(&mut rng).to_repr().as_ref());
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

    let sp = SetupParams {
        nodes: SECTOR_NODES,
        degree: DRG_PARENTS,
        expansion_degree: EXP_PARENTS,
        porep_id: [44; 32],
        layer_challenges: layer_challenges.clone(),
        api_version: ApiVersion::V1_1_0,
    };

    let pp = StackedDrg::<TreeR<F, U, V, W>, Sha256Hasher<F>>::setup(&sp).unwrap();

    let (tau, (p_aux, t_aux)) = StackedDrg::<TreeR<F, U, V, W>, Sha256Hasher<F>>::replicate(
        &pp,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        None,
        config,
        replica_path.clone(),
    )
    .expect("replication failed");

    let mut copied = vec![0; sector_bytes];
    copied.copy_from_slice(&mmapped_data);
    assert_ne!(data, copied, "replication did not change data");

    let seed = rng.gen();
    let vanilla_pub_inputs = vanilla::PublicInputs {
        replica_id: replica_id.into(),
        seed,
        tau: Some(tau),
        k: None,
    };

    // Store copy of original t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all elements based on the
    // configs stored in TemporaryAux.
    let t_aux =
        TemporaryAuxCache::new(&t_aux, replica_path).expect("failed to restore contents of t_aux");

    let priv_inputs = vanilla::PrivateInputs { p_aux, t_aux };

    let partition_proofs =
        StackedDrg::prove_all_partitions(&pp, &vanilla_pub_inputs, &priv_inputs, partition_count)
            .expect("failed to generate partition proofs");
    assert_eq!(partition_proofs.len(), partition_count);

    let proofs_are_valid =
        StackedDrg::verify_all_partitions(&pp, &vanilla_pub_inputs, &partition_proofs)
            .expect("failed while trying to verify partition proofs");
    assert!(proofs_are_valid);

    let partition_proof = &partition_proofs[k];

    // Discard cached MTs that are no longer needed.
    TemporaryAux::clear_temp(t_aux_orig).expect("t_aux delete failed");

    let pub_inputs = circuit::PublicInputs::from(sp, vanilla_pub_inputs);
    let pub_inputs_vec = pub_inputs.to_vec();

    let priv_inputs = circuit::PrivateInputs::<F, U, V, W, SECTOR_NODES>::from(partition_proof);

    let circ = SdrPorepCircuit {
        pub_inputs,
        priv_inputs,
    };

    let k = SdrPorepCircuit::<F, U, V, W, SECTOR_NODES>::k();
    let prover = MockProver::run(k, &circ, pub_inputs_vec).unwrap();
    assert!(prover.verify().is_ok());
}

#[test]
fn test_sdr_porep_circuit_2kib_halo2() {
    test_sdr_porep_circuit::<Fp, U8, U0, U0, SECTOR_NODES_2_KIB>();
}

#[test]
fn test_sdr_porep_circuit_4kib_halo2() {
    test_sdr_porep_circuit::<Fp, U8, U2, U0, SECTOR_NODES_4_KIB>();
}

#[test]
fn test_sdr_porep_circuit_8kib_halo2() {
    test_sdr_porep_circuit::<Fp, U8, U4, U0, SECTOR_NODES_8_KIB>();
}

#[test]
fn test_sdr_porep_circuit_16kib_halo2() {
    test_sdr_porep_circuit::<Fp, U8, U8, U0, SECTOR_NODES_16_KIB>();
}

#[test]
fn test_sdr_porep_circuit_32kib_halo2() {
    test_sdr_porep_circuit::<Fp, U8, U8, U2, SECTOR_NODES_32_KIB>();
}
