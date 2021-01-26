use bellperson::{
    bls::{Bls12, Fr},
    util_cs::test_cs::TestConstraintSystem,
    ConstraintSystem,
};
use ff::Field;
use filecoin_hashers::poseidon::PoseidonHasher;
use fr32::{bytes_into_fr, fr_into_bytes};
use generic_array::typenum::U2;
use merkletree::store::StoreConfig;
use pretty_assertions::assert_eq;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    compound_proof,
    drgraph::{graph_height, BucketGraph, BASE_DEGREE},
    gadgets::variables::Root,
    merkle::MerkleProofTrait,
    proof::ProofScheme,
    test_helper::setup_replica,
    util::{data_at_node, default_rows_to_discard},
    TEST_SEED,
};
use storage_proofs_porep::{
    drg::{self, DrgPoRep, DrgPoRepCircuit, DrgPoRepCompound},
    stacked::BINARY_ARITY,
    PoRep,
};
use tempfile::tempdir;

#[test]
fn test_drg_porep_circuit() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let nodes = 16;
    let degree = BASE_DEGREE;
    let challenge = 2;

    let replica_id: Fr = Fr::random(rng);

    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
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

    let data_node: Option<Fr> = Some(
        bytes_into_fr(
            data_at_node(&mmapped_data, challenge).expect("failed to read original data"),
        )
        .unwrap(),
    );

    let sp = drg::SetupParams {
        drg: drg::DrgParams {
            nodes,
            degree,
            expansion_degree: 0,
            porep_id: [32; 32],
        },
        private: false,
        challenges_count: 1,
        api_version: ApiVersion::V1_1_0,
    };

    let pp = DrgPoRep::<PoseidonHasher, BucketGraph<_>>::setup(&sp)
        .expect("failed to create drgporep setup");
    let (tau, aux) = DrgPoRep::<PoseidonHasher, _>::replicate(
        &pp,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        None,
        config,
        replica_path,
    )
    .expect("failed to replicate");

    let pub_inputs = drg::PublicInputs {
        replica_id: Some(replica_id.into()),
        challenges: vec![challenge],
        tau: Some(tau),
    };

    let priv_inputs = drg::PrivateInputs::<PoseidonHasher> {
        tree_d: &aux.tree_d,
        tree_r: &aux.tree_r,
        tree_r_config_rows_to_discard: default_rows_to_discard(nodes, BINARY_ARITY),
    };

    let proof_nc = DrgPoRep::<PoseidonHasher, _>::prove(&pp, &pub_inputs, &priv_inputs)
        .expect("failed to prove");

    assert!(
        DrgPoRep::<PoseidonHasher, _>::verify(&pp, &pub_inputs, &proof_nc)
            .expect("failed to verify"),
        "failed to verify (non circuit)"
    );

    let replica_node: Option<Fr> = Some(proof_nc.replica_nodes[0].data.into());

    let replica_node_path = proof_nc.replica_nodes[0].proof.as_options();
    let replica_root = Root::Val(Some(proof_nc.replica_root.into()));
    let replica_parents = proof_nc
        .replica_parents
        .iter()
        .map(|v| {
            v.iter()
                .map(|(_, parent)| Some(parent.data.into()))
                .collect()
        })
        .collect();
    let replica_parents_paths: Vec<_> = proof_nc
        .replica_parents
        .iter()
        .map(|v| {
            v.iter()
                .map(|(_, parent)| parent.proof.as_options())
                .collect()
        })
        .collect();

    let data_node_path = proof_nc.nodes[0].proof.as_options();
    let data_root = Root::Val(Some(proof_nc.data_root.into()));
    let replica_id = Some(replica_id);

    assert!(
        proof_nc.nodes[0].proof.validate(challenge),
        "failed to verify data commitment"
    );
    assert!(
        proof_nc.nodes[0]
            .proof
            .validate_data(data_node.unwrap().into()),
        "failed to verify data commitment with data"
    );

    let mut cs = TestConstraintSystem::<Bls12>::new();
    DrgPoRepCircuit::<PoseidonHasher>::synthesize(
        cs.namespace(|| "drgporep"),
        vec![replica_node],
        vec![replica_node_path],
        replica_root,
        replica_parents,
        replica_parents_paths,
        vec![data_node],
        vec![data_node_path],
        data_root,
        replica_id,
        false,
    )
    .expect("failed to synthesize circuit");

    if !cs.is_satisfied() {
        println!(
            "failed to satisfy: {:?}",
            cs.which_is_unsatisfied().unwrap()
        );
    }

    assert!(cs.is_satisfied(), "constraints not satisfied");
    assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
    assert_eq!(cs.num_constraints(), 115_660, "wrong number of constraints");

    assert_eq!(cs.get_input(0, "ONE"), Fr::one());

    assert_eq!(
        cs.get_input(1, "drgporep/replica_id/input variable"),
        replica_id.unwrap()
    );

    let generated_inputs =
        <DrgPoRepCompound<_, _> as compound_proof::CompoundProof<_, _>>::generate_public_inputs(
            &pub_inputs,
            &pp,
            None,
        )
        .unwrap();
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

#[test]
fn test_drg_porep_circuit_inputs_and_constraints() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    // 1 GB
    let n = (1 << 30) / 32;
    let m = BASE_DEGREE;
    let tree_depth = graph_height::<U2>(n);

    let mut cs = TestConstraintSystem::<Bls12>::new();
    DrgPoRepCircuit::<PoseidonHasher>::synthesize(
        cs.namespace(|| "drgporep"),
        vec![Some(Fr::random(rng)); 1],
        vec![vec![(vec![Some(Fr::random(rng))], Some(0)); tree_depth]; 1],
        Root::Val(Some(Fr::random(rng))),
        vec![vec![Some(Fr::random(rng)); m]; 1],
        vec![vec![vec![(vec![Some(Fr::random(rng))], Some(0)); tree_depth]; m]; 1],
        vec![Some(Fr::random(rng)); 1],
        vec![vec![(vec![Some(Fr::random(rng))], Some(0)); tree_depth]; 1],
        Root::Val(Some(Fr::random(rng))),
        Some(Fr::random(rng)),
        false,
    )
    .expect("failed to synthesize circuit");

    assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
    assert_eq!(cs.num_constraints(), 170_924, "wrong number of constraints");
}
