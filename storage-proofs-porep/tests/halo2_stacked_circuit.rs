#![allow(unused_imports, dead_code)]

use ff::{Field, PrimeField};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, PoseidonArity};
use generic_array::typenum::{U0, U2, U4, U8};
use halo2_proofs::{dev::MockProver, pasta::Fp};
use log::{info, trace};
use merkletree::store::StoreConfig;
use rand::{rngs::OsRng, Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::sync::Once;
use storage_proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    halo2::{create_proof, verify_proof, CircuitRows, Halo2Field, Halo2Keypair},
    merkle::DiskTree,
    proof::ProofScheme,
    test_helper::setup_replica,
    util::default_rows_to_discard,
    TEST_SEED,
};
use storage_proofs_porep::{
    stacked::{
        self as vanilla,
        halo2::{
            circuit::{self, SdrPorepCircuit, SDR_POREP_CIRCUIT_ID},
            constants::{
                challenge_count, num_layers, DRG_PARENTS, EXP_PARENTS, SECTOR_NODES_16_KIB,
                SECTOR_NODES_2_KIB, SECTOR_NODES_32_KIB, SECTOR_NODES_4_KIB, SECTOR_NODES_8_KIB,
            },
        },
        LayerChallenges, SetupParams, StackedDrg, TemporaryAux, TemporaryAuxCache, BINARY_ARITY,
    },
    PoRep,
};
use tempfile::tempdir;

type TreeR<U, V, W> = DiskTree<PoseidonHasher<Fp>, U, V, W>;

static INIT_LOGGER: Once = Once::new();
fn init_logger() {
    INIT_LOGGER.call_once(|| {
        fil_logger::init();
    });
}

fn test_sdr_porep_circuit<U, V, W, const SECTOR_NODES: usize>(gen_halo2_proof: bool)
where
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    init_logger();
    info!(
        "test_sdr_porep_circuit started [SectorNodes {}]",
        SECTOR_NODES
    );
    let sector_bytes = SECTOR_NODES << 5;
    let num_layers = num_layers(SECTOR_NODES);
    let challenge_count = challenge_count(SECTOR_NODES);
    let layer_challenges = LayerChallenges::new(num_layers, challenge_count);

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let replica_id = Fp::random(&mut rng);

    info!("Generating random data");
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
    info!("Creating replica");
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
        StackedDrg::<TreeR<U, V, W>, Sha256Hasher<Fp>>::setup(&vanilla_setup_params).unwrap();

    let (tau, (p_aux, t_aux)) = StackedDrg::<TreeR<U, V, W>, Sha256Hasher<Fp>>::replicate(
        &vanilla_pub_params,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        None,
        config,
        replica_path.clone(),
    )
    .expect("replication failed");
    info!("Replicate complete");

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
        k: Some(0),
    };

    let vanilla_priv_inputs = vanilla::PrivateInputs { p_aux, t_aux };

    info!("Proving vanilla partition");
    let vanilla_partition_proof = StackedDrg::prove(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &vanilla_priv_inputs,
    )
    .expect("failed to generate partition proofs");
    trace!("Proving vanilla partition complete");

    info!("Verifying all partitions");
    let proof_is_valid = StackedDrg::verify_all_partitions(
        &vanilla_pub_params,
        &vanilla_pub_inputs,
        &[vanilla_partition_proof.clone()],
    )
    .expect("failed to verify partition proof");
    assert!(proof_is_valid);
    trace!("Verifying all partitions complete");

    // Discard cached MTs that are no longer needed.
    TemporaryAux::clear_temp(t_aux_orig).expect("t_aux delete failed");

    let circ_pub_inputs = circuit::PublicInputs::from(vanilla_setup_params, vanilla_pub_inputs);
    let circ_pub_inputs_vec = circ_pub_inputs.to_vec();
    let circ_priv_inputs =
        circuit::PrivateInputs::<Fp, U, V, W, SECTOR_NODES>::from(vanilla_partition_proof);

    let circ = SdrPorepCircuit {
        id: SDR_POREP_CIRCUIT_ID.to_string(),
        pub_inputs: circ_pub_inputs,
        priv_inputs: circ_priv_inputs,
    };

    info!("Prover starting");
    let prover = MockProver::run(circ.k(), &circ, circ_pub_inputs_vec.clone()).unwrap();
    trace!("Prover complete");

    info!("Verify starting");
    assert!(prover.verify().is_ok());
    trace!("Verify complete");

    if gen_halo2_proof {
        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ).unwrap();
        let proof = create_proof(&keypair, circ, &circ_pub_inputs_vec, &mut OsRng)
            .expect("failed to generate halo2 proof");
        verify_proof(&keypair, &proof, &circ_pub_inputs_vec).expect("failed to verify halo2 proof");
    }
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_circuit_2kib_halo2() {
    // Halo2 keygen, proving, and verifying are slow and consume a lot of memory, thus we only test
    // those for a small sector size circuit (the halo2 compound proof tests will run the halo2
    // prover and verifier for larger sector sizes).
    test_sdr_porep_circuit::<U8, U0, U0, SECTOR_NODES_2_KIB>(true);
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_circuit_4kib_halo2() {
    test_sdr_porep_circuit::<U8, U2, U0, SECTOR_NODES_4_KIB>(false);
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_circuit_8kib_halo2() {
    test_sdr_porep_circuit::<U8, U4, U0, SECTOR_NODES_8_KIB>(false);
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_circuit_16kib_halo2() {
    test_sdr_porep_circuit::<U8, U8, U0, SECTOR_NODES_16_KIB>(false);
}

#[cfg(feature = "isolated-testing")]
#[test]
fn test_sdr_porep_circuit_32kib_halo2() {
    test_sdr_porep_circuit::<U8, U8, U2, SECTOR_NODES_32_KIB>(false);
}

#[cfg(feature = "big-tests")]
#[test]
fn test_sdr_porep_circuit_512mib_halo2() {
    use storage_proofs_porep::stacked::halo2::constants::SECTOR_NODES_512_MIB;
    test_sdr_porep_circuit::<U8, U0, U0, SECTOR_NODES_512_MIB>(false);
}

#[cfg(feature = "big-tests")]
#[test]
fn test_sdr_porep_circuit_32gib_halo2() {
    use storage_proofs_porep::stacked::halo2::constants::SECTOR_NODES_32_GIB;
    test_sdr_porep_circuit::<U8, U8, U0, SECTOR_NODES_32_GIB>(false);
}

#[cfg(feature = "big-tests")]
#[test]
fn test_sdr_porep_circuit_64gib_halo2() {
    use storage_proofs_porep::stacked::halo2::constants::SECTOR_NODES_64_GIB;
    test_sdr_porep_circuit::<U8, U8, U2, SECTOR_NODES_64_GIB>(false);
}
