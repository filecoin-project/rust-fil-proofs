use bellperson::{
    util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem},
    Circuit, ConstraintSystem,
};
use blstrs::Scalar as Fr;
use ff::{Field, PrimeField, PrimeFieldBits};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher, R1CSHasher};
use generic_array::typenum::{U0, U2, U4, U8};
use merkletree::store::StoreConfig;
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
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher<Fr>, U2, U0, U0>>(22, 1_206_212);
}

#[test]
fn test_stacked_input_circuit_poseidon_base_8() {
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher<Fr>, U8, U0, U0>>(22, 1_199_620);
}

#[test]
fn test_stacked_input_circuit_poseidon_sub_8_4() {
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher<Fr>, U8, U4, U0>>(22, 1_296_576);
}

#[test]
fn test_stacked_input_circuit_poseidon_top_8_4_2() {
    test_stacked_porep_circuit::<DiskTree<PoseidonHasher<Fr>, U8, U4, U2>>(22, 1_346_982);
}

fn test_stacked_porep_circuit<Tree>(expected_inputs: usize, expected_constraints: usize)
where
    Tree: 'static + MerkleTreeTrait,
    Tree::Hasher: R1CSHasher,
    Tree::Field: PrimeFieldBits,
    Sha256Hasher<Tree::Field>: R1CSHasher<Field = Tree::Field>,
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

    let pp = StackedDrg::<Tree, Sha256Hasher<Tree::Field>>::setup(&sp).expect("setup failed");
    let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, Sha256Hasher<Tree::Field>>::replicate(
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
    let pub_inputs = PublicInputs::<
        <Tree::Hasher as Hasher>::Domain,
        <Sha256Hasher<Tree::Field> as Hasher>::Domain,
    > {
        replica_id: replica_id.into(),
        seed,
        tau: Some(tau),
        k: None,
    };

    // Store copy of original t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, Sha256Hasher<Tree::Field>>::new(&t_aux, replica_path)
        .expect("failed to restore contents of t_aux");

    let priv_inputs = PrivateInputs::<Tree, Sha256Hasher<Tree::Field>> { p_aux, t_aux };

    let proofs = StackedDrg::<Tree, Sha256Hasher<Tree::Field>>::prove_all_partitions(
        &pp,
        &pub_inputs,
        &priv_inputs,
        1,
    )
    .expect("failed to generate partition proofs");

    let proofs_are_valid = StackedDrg::<Tree, Sha256Hasher<Tree::Field>>::verify_all_partitions(
        &pp,
        &pub_inputs,
        &proofs,
    )
    .expect("failed while trying to verify partition proofs");

    assert!(proofs_are_valid);
    let vanilla_proof = &proofs[0];

    // Discard cached MTs that are no longer needed.
    TemporaryAux::<Tree, Sha256Hasher<Tree::Field>>::clear_temp(t_aux_orig)
        .expect("t_aux delete failed");

    {
        // Verify that MetricCS returns the same metrics as TestConstraintSystem.
        let mut cs = MetricCS::<Tree::Field>::new();

        let circ = StackedCircuit::<'_, Tree, Sha256Hasher<Tree::Field>> {
            public_params: pp.clone(),
            replica_id: Some(pub_inputs.replica_id),
            comm_d: pub_inputs.tau.as_ref().map(|t| t.comm_d),
            comm_r: pub_inputs.tau.as_ref().map(|t| t.comm_r),
            comm_r_last: Some(vanilla_proof[0].comm_r_last()),
            comm_c: Some(vanilla_proof[0].comm_c()),
            proofs: vanilla_proof.iter().cloned().map(|p| p.into()).collect(),
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

    let circ = StackedCircuit::<'_, Tree, Sha256Hasher<Tree::Field>> {
        public_params: pp.clone(),
        replica_id: Some(pub_inputs.replica_id),
        comm_d: pub_inputs.tau.as_ref().map(|t| t.comm_d),
        comm_r: pub_inputs.tau.as_ref().map(|t| t.comm_r),
        comm_r_last: Some(vanilla_proof[0].comm_r_last()),
        comm_c: Some(vanilla_proof[0].comm_c()),
        proofs: vanilla_proof.iter().cloned().map(|p| p.into()).collect(),
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

    let generated_inputs =
        StackedCircuit::<'_, Tree, Sha256Hasher<Tree::Field>>::generate_public_inputs(
            &pp,
            &pub_inputs,
            None,
        )
        .expect("failed to generate r1cs circuit's public inputs");
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
