use bellperson::{
    bls::Fr,
    util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem},
    Circuit,
};
use ff::Field;
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher};
use fr32::fr_into_bytes;
use generic_array::typenum::{U0, U2, U4, U8};
use merkletree::store::StoreConfig;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    compound_proof::{self, CompoundProof},
    drgraph::BASE_DEGREE,
    merkle::{get_base_tree_count, DiskTree, MerkleTreeTrait},
    test_helper::setup_replica,
    util::default_rows_to_discard,
    TEST_SEED,
};
use storage_proofs_porep::{
    stacked::{
        ChallengeRequirements, LayerChallenges, PrivateInputs, PublicInputs, SetupParams,
        StackedCompound, StackedDrg, TemporaryAux, TemporaryAuxCache, BINARY_ARITY, EXP_DEGREE,
    },
    PoRep,
};
use tempfile::tempdir;

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
    let layer_challenges = LayerChallenges::new(num_layers, 1);
    let partition_count = 1;

    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let replica_id: Fr = Fr::random(rng);
    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
        .collect();

    let arbitrary_porep_id = [55; 32];
    let setup_params = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            nodes,
            degree,
            expansion_degree,
            porep_id: arbitrary_porep_id,
            layer_challenges,
            api_version: ApiVersion::V1_1_0,
        },
        partitions: Some(partition_count),
        priority: false,
    };

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

    let public_params = StackedCompound::setup(&setup_params).expect("setup failed");
    let (tau, (p_aux, t_aux)) = StackedDrg::<Tree, _>::replicate(
        &public_params.vanilla_params,
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
    let public_inputs =
        PublicInputs::<<Tree::Hasher as Hasher>::Domain, <Sha256Hasher as Hasher>::Domain> {
            replica_id: replica_id.into(),
            seed,
            tau: Some(tau),
            k: None,
        };

    // Store a copy of the t_aux for later resource deletion.
    let t_aux_orig = t_aux.clone();

    // Convert TemporaryAux to TemporaryAuxCache, which instantiates all
    // elements based on the configs stored in TemporaryAux.
    let t_aux = TemporaryAuxCache::<Tree, _>::new(&t_aux, replica_path)
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
    >>::groth_params(Some(rng), &public_params.vanilla_params)
    .expect("failed to generate groth params");

    // Discard cached MTs that are no longer needed.
    TemporaryAux::<Tree, Sha256Hasher>::clear_temp(t_aux_orig).expect("t_aux delete failed");

    let proof = StackedCompound::prove(
        &public_params,
        &public_inputs,
        &private_inputs,
        &blank_groth_params,
    )
    .expect("failed while proving");

    let verified = StackedCompound::verify(
        &public_params,
        &public_inputs,
        &proof,
        &ChallengeRequirements {
            minimum_challenges: 1,
        },
    )
    .expect("failed while verifying");

    assert!(verified);

    cache_dir.close().expect("Failed to remove cache dir");
}
