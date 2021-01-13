use bellperson::{
    bls::Fr,
    util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem},
    Circuit,
};
use ff::Field;
use filecoin_hashers::{poseidon::PoseidonHasher, Hasher};
use fr32::fr_into_bytes;
use merkletree::store::StoreConfig;
use pretty_assertions::assert_eq;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    cache_key::CacheKey,
    compound_proof::{self, CompoundProof},
    drgraph::{BucketGraph, BASE_DEGREE},
    merkle::{BinaryMerkleTree, MerkleTreeTrait},
    proof::NoRequirements,
    test_helper::setup_replica,
    util::default_rows_to_discard,
    TEST_SEED,
};
use storage_proofs_porep::{
    drg::{DrgParams, DrgPoRep, DrgPoRepCompound, PrivateInputs, PublicInputs, SetupParams},
    stacked::BINARY_ARITY,
    PoRep,
};
use tempfile::tempdir;

#[test]
#[ignore]
fn test_drg_porep_compound_poseidon() {
    drg_porep_compound::<BinaryMerkleTree<PoseidonHasher>>();
}

fn drg_porep_compound<Tree: 'static + MerkleTreeTrait>() {
    // femme::pretty::Logger::new()
    //     .start(log::LevelFilter::Trace)
    //     .ok();

    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let nodes = 8;
    let degree = BASE_DEGREE;
    let challenges = vec![1, 3];

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

    let setup_params = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            drg: DrgParams {
                nodes,
                degree,
                expansion_degree: 0,
                porep_id: [32; 32],
            },
            private: false,
            challenges_count: 2,
            api_version: ApiVersion::V1_1_0,
        },
        partitions: None,
        priority: false,
    };

    let public_params =
        DrgPoRepCompound::<Tree::Hasher, BucketGraph<Tree::Hasher>>::setup(&setup_params)
            .expect("setup failed");

    let data_tree: Option<BinaryMerkleTree<Tree::Hasher>> = None;
    let (tau, aux) = DrgPoRep::<Tree::Hasher, BucketGraph<_>>::replicate(
        &public_params.vanilla_params,
        &replica_id.into(),
        (mmapped_data.as_mut()).into(),
        data_tree,
        config,
        replica_path,
    )
    .expect("failed to replicate");

    let public_inputs = PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
        replica_id: Some(replica_id.into()),
        challenges,
        tau: Some(tau),
    };
    let private_inputs = PrivateInputs {
        tree_d: &aux.tree_d,
        tree_r: &aux.tree_r,
        tree_r_config_rows_to_discard: default_rows_to_discard(nodes, BINARY_ARITY),
    };

    // This duplication is necessary so public_params don't outlive public_inputs and private_inputs.
    let setup_params = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            drg: DrgParams {
                nodes,
                degree,
                expansion_degree: 0,
                porep_id: [32; 32],
            },
            private: false,
            challenges_count: 2,
            api_version: ApiVersion::V1_1_0,
        },
        partitions: None,
        priority: false,
    };

    let public_params =
        DrgPoRepCompound::<Tree::Hasher, BucketGraph<Tree::Hasher>>::setup(&setup_params)
            .expect("setup failed");

    {
        let (circuit, inputs) = DrgPoRepCompound::<Tree::Hasher, _>::circuit_for_test(
            &public_params,
            &public_inputs,
            &private_inputs,
        )
        .unwrap();

        let mut cs = TestConstraintSystem::new();

        circuit
            .synthesize(&mut cs)
            .expect("failed to synthesize test circuit");
        assert!(cs.is_satisfied());
        assert!(cs.verify(&inputs));

        let blank_circuit = <DrgPoRepCompound<_, _> as CompoundProof<_, _>>::blank_circuit(
            &public_params.vanilla_params,
        );

        let mut cs_blank = MetricCS::new();
        blank_circuit
            .synthesize(&mut cs_blank)
            .expect("failed to synthesize blank circuit");

        let a = cs_blank.pretty_print_list();
        let b = cs.pretty_print_list();

        for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
            assert_eq!(a, b, "failed at chunk {}", i);
        }
    }

    {
        let gparams = DrgPoRepCompound::<Tree::Hasher, _>::groth_params(
            Some(rng),
            &public_params.vanilla_params,
        )
        .expect("failed to get groth params");

        let proof = DrgPoRepCompound::<Tree::Hasher, _>::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
            &gparams,
        )
        .expect("failed while proving");

        let verified = DrgPoRepCompound::<Tree::Hasher, _>::verify(
            &public_params,
            &public_inputs,
            &proof,
            &NoRequirements,
        )
        .expect("failed while verifying");

        assert!(verified);
    }

    cache_dir.close().expect("Failed to remove cache dir");
}
