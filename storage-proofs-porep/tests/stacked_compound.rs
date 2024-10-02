use bellperson::{
    groth16,
    util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem},
    Circuit,
};
use blstrs::Scalar as Fr;
use ff::Field;
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher};
use fr32::fr_into_bytes;
use generic_array::typenum::{U0, U2, U4, U8};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    compound_proof::{self, CompoundProof},
    drgraph::BASE_DEGREE,
    merkle::{get_base_tree_count, DiskTree, MerkleTreeTrait},
    multi_proof::MultiProof,
    test_helper::setup_replica,
    TEST_SEED,
};
use storage_proofs_porep::stacked::{
    self, ChallengeRequirements, Challenges, PrivateInputs, PublicInputs, SetupParams,
    StackedCompound, StackedDrg, TemporaryAuxCache, EXP_DEGREE,
};
use tempfile::tempdir;

mod common;

#[test]
#[ignore]
fn test_stacked_compound_poseidon_base_8() {
    test_stacked_compound::<DiskTree<PoseidonHasher, U8, U0, U0>>();
}

#[test]
#[ignore]
fn test_stacked_compound_poseidon_sub_8_4() {
    test_stacked_compound::<DiskTree<PoseidonHasher, U8, U4, U0>>();
}

#[test]
#[ignore]
fn test_stacked_compound_poseidon_top_8_4_2() {
    test_stacked_compound::<DiskTree<PoseidonHasher, U8, U4, U2>>();
}

fn test_stacked_compound<Tree: 'static + MerkleTreeTrait>() {
    let nodes = 8 * get_base_tree_count::<Tree>();

    let degree = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let num_layers = 2;
    let challenges = Challenges::new_interactive(1);
    let partition_count = 1;

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let replica_id: Fr = Fr::random(&mut rng);
    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| fr_into_bytes(&Fr::random(&mut rng)))
        .collect();

    let arbitrary_porep_id = [55; 32];
    let setup_params = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            nodes,
            degree,
            expansion_degree,
            porep_id: arbitrary_porep_id,
            challenges,
            num_layers,
            api_version: ApiVersion::V1_1_0,
            api_features: vec![],
        },
        partitions: Some(partition_count),
        priority: false,
    };

    // MT for original data is always named tree-d, and it will be
    // referenced later in the process as such.
    let cache_dir = tempdir().unwrap();

    // Generate a replica path.
    let replica_path = cache_dir.path().join("replica-path");
    let mut mmapped_data = setup_replica(&data, &replica_path);

    let public_params = StackedCompound::setup(&setup_params).expect("setup failed");
    let (tau, (p_aux, t_aux)) = common::transform_and_replicate_layers::<Tree, _>(
        &public_params.vanilla_params,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        cache_dir.path().to_path_buf(),
        replica_path.clone(),
    );

    let mut copied = vec![0; data.len()];
    copied.copy_from_slice(&mmapped_data);
    assert_ne!(data, copied, "replication did not change data");

    let seed = rng.gen();
    let public_inputs =
        PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Domain> {
            replica_id: replica_id.into(),
            seed: Some(seed),
            tau: Some(tau),
            k: None,
        };

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, _>::new(&t_aux, replica_path, false)
        .expect("failed to restore contents of t_aux");

    let private_inputs = PrivateInputs::<Tree, Sha256Hasher> { p_aux, t_aux };

    {
        let (circuit, inputs) =
            StackedCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                .unwrap();

        let mut cs = TestConstraintSystem::new();

        circuit.synthesize(&mut cs).expect("failed to synthesize");

        if !cs.is_satisfied() {
            panic!(
                "failed to satisfy: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }
        assert!(
            cs.verify(&inputs),
            "verification failed with TestContraintSystem and generated inputs"
        );
    }

    // Use this to debug differences between blank and regular circuit generation.
    {
        let (circuit1, _inputs) =
            StackedCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                .unwrap();
        let blank_circuit = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
            StackedDrg<'_, Tree, Sha256Hasher>,
            _,
        >>::blank_circuit(&public_params.vanilla_params);

        let mut cs_blank = MetricCS::new();
        blank_circuit
            .synthesize(&mut cs_blank)
            .expect("failed to synthesize");

        let a = cs_blank.pretty_print_list();

        let mut cs1 = TestConstraintSystem::new();
        circuit1.synthesize(&mut cs1).expect("failed to synthesize");
        let b = cs1.pretty_print_list();

        for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
            assert_eq!(a, b, "failed at chunk {}", i);
        }
    }

    let blank_groth_params = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
        StackedDrg<'_, Tree, Sha256Hasher>,
        _,
    >>::groth_params(Some(&mut rng), &public_params.vanilla_params)
    .expect("failed to generate groth params");

    // Discard cached MTs that are no longer needed.
    stacked::clear_cache_dir(cache_dir.path()).expect("cached files delete failed");

    // Discard normally permanent files no longer needed in testing.
    common::remove_replica_and_tree_r::<Tree>(cache_dir.path())
        .expect("failed to remove replica and tree_r");

    let proofs = StackedCompound::prove(
        &public_params,
        &public_inputs,
        &private_inputs,
        &blank_groth_params,
    )
    .expect("failed while proving");

    // Don't try to generate the groth parameters, as they should already have been generated by
    // the `groth_params()` call above.
    let verifying_key = StackedCompound::<Tree, Sha256Hasher>::verifying_key::<XorShiftRng>(
        None,
        &public_params.vanilla_params,
    )
    .expect("failed to get veriyfing key");
    let prepared_verifying_key = groth16::prepare_verifying_key(&verifying_key);
    let multi_proof = MultiProof::new(proofs, &prepared_verifying_key);

    let verified = StackedCompound::verify(
        &public_params,
        &public_inputs,
        &multi_proof,
        &ChallengeRequirements {
            minimum_challenges: 1,
        },
    )
    .expect("failed while verifying");

    assert!(verified);

    if std::fs::remove_dir(cache_dir.path()).is_ok() && cache_dir.path().exists() {
        let _ = cache_dir.close();
    }
}
