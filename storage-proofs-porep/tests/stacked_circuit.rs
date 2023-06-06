use bellperson::{
    util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem},
    Circuit, ConstraintSystem,
};
use ff::{Field, PrimeField, PrimeFieldBits};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher};
use generic_array::typenum::{U0, U2, U4, U8};
use merkletree::store::StoreConfig;
#[cfg(feature = "nova")]
use pasta_curves::Fp;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    drgraph::BASE_DEGREE,
    merkle::{get_base_tree_count, DiskTree, MerkleTreeTrait},
    proof::ProofScheme,
    test_helper::setup_replica,
    util::default_rows_to_discard,
    TEST_SEED,
};
use storage_proofs_porep::{
    stacked::{
        LayerChallenges, PrivateInputs, PublicInputs, SetupParams, StackedCircuit, StackedDrg,
        TemporaryAux, TemporaryAuxCache, BINARY_ARITY, EXP_DEGREE,
    },
    PoRep,
};
use tempfile::tempdir;

#[test]
fn test_stacked_porep_circuit_poseidon_base_2() {
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher, U2, U0, U0>>(22, 1_206_212);
    #[cfg(feature = "nova")]
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher<Fp>, U2, U0, U0>>(22, 1_206_212);
}

#[test]
fn test_stacked_input_circuit_poseidon_base_8() {
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher, U8, U0, U0>>(22, 1_199_620);
    #[cfg(feature = "nova")]
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher<Fp>, U8, U0, U0>>(22, 1_199_620);
}

#[test]
fn test_stacked_input_circuit_poseidon_sub_8_4() {
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher, U8, U4, U0>>(22, 1_296_576);
    #[cfg(feature = "nova")]
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher<Fp>, U8, U4, U0>>(22, 1_296_576);
}

#[test]
fn test_stacked_input_circuit_poseidon_top_8_4_2() {
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher, U8, U4, U2>>(22, 1_346_982);
    #[cfg(feature = "nova")]
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher<Fp>, U8, U4, U2>>(22, 1_346_982);
}

fn test_stacked_porep_circuit<Tree: MerkleTreeTrait + 'static>(
    expected_inputs: usize,
    expected_constraints: usize,
)
where
    Tree::Field: PrimeFieldBits,
    Sha256Hasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    let nodes = 8 * get_base_tree_count::<Tree>();
    let degree = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let num_layers = 2;
    let layer_challenges = LayerChallenges::new(num_layers, 1);

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let replica_id = Tree::Field::random(&mut rng);
    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| Tree::Field::random(&mut rng).to_repr().as_ref().to_vec())
        .collect();

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempdir().unwrap();
    let config = StoreConfig::new(
        cache_dir.path(),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(nodes, BINARY_ARITY),
    );

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let arbitrary_porep_id = [44; 32];
    let sp = SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id: arbitrary_porep_id,
        layer_challenges,
        api_version: ApiVersion::V1_1_0,
    };

    let pp = StackedDrg::<Tree, Sha256Hasher<_>>::setup(&sp).expect("setup failed");
    let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, Sha256Hasher<_>>::replicate(
        &pp,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        None,
        config,
        replica_path.clone(),
    )
    .expect("replication failed");

    let mut copied = vec![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne!(data, copied, "replication did not change data");

    let seed = rng.gen();
    let pub_inputs =
        PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Sha256Hasher<_> as Hasher>::Domain> {
            replica_id: replica_id.into(),
            seed,
            tau: Some(tau),
            k: None,
        };

    // Store copy of original t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, Sha256Hasher<_>>::new(&t_aux, replica_path)
        .expect("failed to restore contents of t_aux");

    let priv_inputs = PrivateInputs::<Tree, Sha256Hasher<_>> { p_aux, t_aux };

    let proofs =
        StackedDrg::<Tree, Sha256Hasher<_>>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, 1)
            .expect("failed to generate partition proofs");

    let proofs_are_valid =
        StackedDrg::<Tree, Sha256Hasher<_>>::verify_all_partitions(&pp, &pub_inputs, &proofs)
            .expect("failed while trying to verify partition proofs");

    assert!(proofs_are_valid);
    let proofs = &proofs[0];

    // Discard cached MTs that are no longer needed.
    TemporaryAux::<Tree, Sha256Hasher<_>>::clear_temp(t_aux_orig).expect("t_aux delete failed");

    {
        // Verify that MetricCS returns the same metrics as TestConstraintSystem.
        let mut cs = MetricCS::<Tree::Field>::new();

        let circ = StackedCircuit::<'_, Tree, Sha256Hasher<_>> {
            public_params: pp.clone(),
            replica_id: Some(pub_inputs.replica_id),
            comm_d: pub_inputs.tau.as_ref().map(|t| t.comm_d),
            comm_r: pub_inputs.tau.as_ref().map(|t| t.comm_r),
            comm_r_last: Some(proofs[0].comm_r_last()),
            comm_c: Some(proofs[0].comm_c()),
            proofs: proofs.iter().cloned().map(|p| p.into()).collect(),
        };

        circ.synthesize(&mut cs.namespace(|| "stacked drgporep"))
            .expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), expected_inputs, "wrong number of inputs");
        assert_eq!(
            cs.num_constraints(),
            expected_constraints,
            "wrong number of constraints"
        );
    }
    let mut cs = TestConstraintSystem::<Tree::Field>::new();

    let circ = StackedCircuit::<'_, Tree, Sha256Hasher<_>> {
        public_params: pp.clone(),
        replica_id: Some(pub_inputs.replica_id),
        comm_d: pub_inputs.tau.as_ref().map(|t| t.comm_d),
        comm_r: pub_inputs.tau.as_ref().map(|t| t.comm_r),
        comm_r_last: Some(proofs[0].comm_r_last()),
        comm_c: Some(proofs[0].comm_c()),
        proofs: proofs.iter().cloned().map(|p| p.into()).collect(),
    };

    circ.synthesize(&mut cs.namespace(|| "stacked drgporep"))
        .expect("failed to synthesize circuit");

    assert!(cs.is_satisfied(), "constraints not satisfied");
    assert_eq!(cs.num_inputs(), expected_inputs, "wrong number of inputs");
    assert_eq!(
        cs.num_constraints(),
        expected_constraints,
        "wrong number of constraints"
    );

    assert_eq!(cs.get_input(0, "ONE"), Tree::Field::one());

    let generated_inputs = StackedCircuit::<'_, Tree, Sha256Hasher<_>>::generate_public_inputs(
        &pp,
        &pub_inputs,
        None,
    )
    .expect("failed to generate public inputs");
    let expected_inputs = cs.get_inputs();

    for ((input, label), generated_input) in
        expected_inputs.iter().skip(1).zip(generated_inputs.iter())
    {
        assert_eq!(input, generated_input, "{}", label);
    }

    assert_eq!(
        generated_inputs.len(),
        expected_inputs.len() - 1,
        "inputs are not the same length"
    );

    cache_dir.close().expect("Failed to remove cache dir");
}

use blstrs::Scalar as Fr;

fn test_aggregate_inner<Tree>(
    sector_nodes: usize,
    num_layers: usize,
    porep_challenges: usize,
    partition_count: usize,
    num_sectors: usize,
)
where
    Tree: 'static + MerkleTreeTrait<Field = Fr>,
    Sha256Hasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    use std::time::Instant;

    use log::info;

    fil_logger::maybe_init();

    let partition_challenge_count = porep_challenges / partition_count;
    let num_partition_proofs = num_sectors * partition_count;
    let num_agg_proofs = std::cmp::max(num_partition_proofs.next_power_of_two(), 2);

    info!(
        "Groth16 PoRep aggregation test:\
        \n    sector-size={}\
        \n    layers={}\
        \n    porep-challenges={}\
        \n    partition-challenges={}\
        \n    num-sectors={}\
        \n    num-proofs-aggregated={}",
        storage_proofs_core::util::pretty_print_sector_size(sector_nodes),
        num_layers,
        porep_challenges,
        partition_challenge_count,
        num_sectors,
        num_agg_proofs,
    );

    let sp = SetupParams {
        nodes: sector_nodes,
        degree: BASE_DEGREE,
        expansion_degree: EXP_DEGREE,
        porep_id: [44; 32],
        layer_challenges: LayerChallenges::new(num_layers, partition_challenge_count),
        api_version: ApiVersion::V1_1_0,
    };

    let pp = StackedDrg::<Tree, Sha256Hasher>::setup(&sp).expect("setup failed");

    let circ = if cfg!(feature = "mock-test-circ") {
        info!("generating mock partition circuit");
        StackedCircuit::<'_, Tree, Sha256Hasher>::mock(pp)
    } else {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        let replica_id = Tree::Field::random(&mut rng);
        let data: Vec<u8> = (0..sector_nodes)
            .flat_map(|_| Tree::Field::random(&mut rng).to_repr().as_ref().to_vec())
            .collect();

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        let cache_dir = tempdir().unwrap();
        let config = StoreConfig::new(
            cache_dir.path(),
            CacheKey::CommDTree.to_string(),
            default_rows_to_discard(sector_nodes, BINARY_ARITY),
        );

        // Generate a replica path.
        let replica_path = cache_dir.path().join("replica-path");
        let mut mmapped_data = setup_replica(&data, &replica_path);

        let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, Sha256Hasher>::replicate(
            &pp,
            &replica_id.into(),
            (mmapped_data.as_mut()).into(),
            None,
            config,
            replica_path.clone(),
        )
        .expect("replication failed");

        let mut copied = vec![0; data.len()];
        copied.copy_from_slice(&mmapped_data);
        assert_ne!(data, copied, "replication did not change data");

        let seed = rng.gen();
        let pub_inputs =
            PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Domain> {
                replica_id: replica_id.into(),
                seed,
                tau: Some(tau),
                k: None,
            };

        // Store copy of original t_aux for later resource deletion.
        let t_aux_orig = t_aux.clone();

        // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
        // elements based on the configs stored in TemporaryAux.
        let t_aux = TemporaryAuxCache::<Tree, Sha256Hasher>::new(&t_aux, replica_path)
            .expect("failed to restore contents of t_aux");

        let priv_inputs = PrivateInputs::<Tree, Sha256Hasher> { p_aux, t_aux };

        let proofs =
            StackedDrg::<Tree, Sha256Hasher>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, 1)
                .expect("failed to generate partition proofs");

        let proofs_are_valid =
            StackedDrg::<Tree, Sha256Hasher>::verify_all_partitions(&pp, &pub_inputs, &proofs)
                .expect("failed while trying to verify partition proofs");

        assert!(proofs_are_valid);
        let proofs = &proofs[0];

        // Discard cached MTs that are no longer needed.
        TemporaryAux::<Tree, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

        StackedCircuit::<'_, Tree, Sha256Hasher> {
            public_params: pp.clone(),
            replica_id: Some(pub_inputs.replica_id),
            comm_d: pub_inputs.tau.as_ref().map(|t| t.comm_d),
            comm_r: pub_inputs.tau.as_ref().map(|t| t.comm_r),
            comm_r_last: Some(proofs[0].comm_r_last()),
            comm_c: Some(proofs[0].comm_c()),
            proofs: proofs.iter().cloned().map(|p| p.into()).collect(),
        }
    };

    /*
    let mut cs = TestConstraintSystem::<Tree::Field>::new();
    circ.synthesize(&mut cs.namespace(|| "stacked drgporep"))
        .expect("failed to synthesize circuit");
    dbg!(cs.num_inputs());
    dbg!(cs.num_constraints());
    assert!(cs.is_satisfied(), "constraints not satisfied");
    */

    let rng = &mut rand::rngs::OsRng;

    info!("generating Groth16 params");
    let start = Instant::now();
    let groth_params =
        bellperson::groth16::generate_random_parameters::<blstrs::Bls12, _, _>(circ.clone(), rng)
            .unwrap();
    info!("successfully generated Groth16 params ({}s)", start.elapsed().as_secs_f32());

    info!("preparing Groth16 vk");
    let pvk = bellperson::groth16::prepare_verifying_key(&groth_params.vk);
    info!("successfully prepared Groth16 vk");

    info!("generating aggregation srs");
    let start = Instant::now();
    let (agg_pk, agg_vk) =
        bellperson::groth16::aggregate::setup_fake_srs::<blstrs::Bls12, _>(rng, num_agg_proofs)
            .specialize(num_agg_proofs);
    info!("successfully generated aggregation srs ({}s)", start.elapsed().as_secs_f32());

    let circs = vec![circ; num_partition_proofs];
    let mut pub_inputs = vec![circs[0].pub_inputs_vec(); num_partition_proofs];

    info!("generating Groth16 batch proof (num-partition-proofs={})", num_partition_proofs);
    let start = Instant::now();
    let mut groth_proofs = bellperson::groth16::create_random_proof_batch(circs, &groth_params, rng).unwrap();
    info!("successfully generated Groth16 batch proof ({}s)", start.elapsed().as_secs_f32());

    info!("verifying Groth16 batch proof");
    let start = Instant::now();
    let is_valid = bellperson::groth16::verify_proofs_batch(
        &pvk,
        rng,
        &groth_proofs.iter().collect::<Vec<&_>>(),
        &pub_inputs,
    )
    .unwrap();
    assert!(is_valid);
    info!("successfully verified Groth16 batch proof ({}s)", start.elapsed().as_secs_f32());

    info!("padding Groth16 proofs for aggregation: {} -> {}", num_partition_proofs, num_agg_proofs);
    groth_proofs.resize(num_agg_proofs, groth_proofs.last().unwrap().clone());
    pub_inputs.resize(num_agg_proofs, pub_inputs.last().unwrap().clone());

    info!("generating aggregation proof");
    let start = Instant::now();
    let agg_proof = bellperson::groth16::aggregate::aggregate_proofs::<blstrs::Bls12>(
        &agg_pk,
        &[],
        &groth_proofs,
        bellperson::groth16::aggregate::AggregateVersion::V2,
    )
    .unwrap();
    info!("successfully generated aggregation proof ({}s)", start.elapsed().as_secs_f32());

    info!("verifying aggregation proof");
    let start = Instant::now();
    let is_valid = bellperson::groth16::aggregate::verify_aggregate_proof(
        &agg_vk,
        &pvk,
        rng,
        &pub_inputs,
        &agg_proof,
        &[],
        bellperson::groth16::aggregate::AggregateVersion::V2,
    )
    .unwrap();
    assert!(is_valid);
    info!("successfully verified aggregation proof ({}s)", start.elapsed().as_secs_f32());
}

#[test]
fn test_aggregate() {
    let sector_nodes = storage_proofs_core::SECTOR_NODES_2_KIB;
    let num_layers = 2;
    let porep_challenges = 6;
    let partition_count = 3;
    let num_sectors = 2;

    test_aggregate_inner::<DiskTree<PoseidonHasher, U8, U0, U0>>(
        sector_nodes,
        num_layers,
        porep_challenges,
        partition_count,
        num_sectors,
    );
}
