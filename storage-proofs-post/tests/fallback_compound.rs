use bellperson::{
    util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem},
    Circuit,
};
use filecoin_hashers::{poseidon::PoseidonHasher, Domain, HashFunction, Hasher};
use generic_array::typenum::{U0, U2, U4, U8};
use pretty_assertions::assert_eq;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    compound_proof::{self, CompoundProof},
    merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    util::NODE_SIZE,
    TEST_SEED,
};
use storage_proofs_post::fallback::{
    ChallengeRequirements, FallbackPoStCompound, PrivateInputs, PrivateSector, PublicInputs,
    PublicSector, SetupParams,
};
use tempfile::tempdir;

#[ignore]
#[test]
fn test_fallback_post_compound_poseidon_single_partition_base_8() {
    fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(15, 15, 1, ApiVersion::V1_0_0);
    fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(15, 15, 1, ApiVersion::V1_1_0);
}

#[ignore]
#[test]
fn test_fallback_post_compound_poseidon_single_partition_sub_8_4() {
    fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 3, 1, ApiVersion::V1_0_0);
    fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 3, 1, ApiVersion::V1_1_0);
}

#[ignore]
#[test]
fn test_fallback_post_compound_poseidon_single_partition_top_8_4_2() {
    fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 3, 1, ApiVersion::V1_0_0);
    fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 3, 1, ApiVersion::V1_1_0);
}

#[ignore]
#[test]
fn test_fallback_post_compound_poseidon_single_partition_smaller_base_8() {
    fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(2, 3, 1, ApiVersion::V1_0_0);
    fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(2, 3, 1, ApiVersion::V1_1_0);
}

#[ignore]
#[test]
fn test_fallback_post_compound_poseidon_two_partitions_base_8() {
    fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2, ApiVersion::V1_0_0);
    fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[ignore]
#[test]
fn test_fallback_post_compound_poseidon_two_partitions_smaller_base_8() {
    fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2, ApiVersion::V1_0_0);
    fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2, ApiVersion::V1_1_0);
}

fn fallback_post<Tree: 'static + MerkleTreeTrait>(
    total_sector_count: usize,
    sector_count: usize,
    partitions: usize,
    api_version: ApiVersion,
) where
    Tree::Store: 'static,
{
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = (leaves * NODE_SIZE) as u64;
    let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
    let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);
    let challenge_count = 2;

    let setup_params = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            sector_size: sector_size as u64,
            challenge_count,
            sector_count,
            api_version,
        },
        partitions: Some(partitions),
        priority: false,
    };

    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    let mut pub_sectors = Vec::new();
    let mut priv_sectors = Vec::new();
    let mut trees = Vec::new();

    for _i in 0..total_sector_count {
        let (_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        trees.push(tree);
    }
    for (i, tree) in trees.iter().enumerate() {
        let comm_c = <Tree::Hasher as Hasher>::Domain::random(rng);
        let comm_r_last = tree.root();

        priv_sectors.push(PrivateSector {
            tree,
            comm_c,
            comm_r_last,
        });

        let comm_r = <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);
        pub_sectors.push(PublicSector {
            id: (i as u64).into(),
            comm_r,
        });
    }

    let pub_params = FallbackPoStCompound::<Tree>::setup(&setup_params).expect("setup failed");

    let pub_inputs = PublicInputs {
        randomness,
        prover_id,
        sectors: pub_sectors.clone(),
        k: None,
    };

    let priv_inputs = PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    // Use this to debug differences between blank and regular circuit generation.
    {
        let circuits =
            FallbackPoStCompound::circuit_for_test_all(&pub_params, &pub_inputs, &priv_inputs)
                .unwrap();
        let blank_circuit = FallbackPoStCompound::<Tree>::blank_circuit(&pub_params.vanilla_params);

        let mut cs_blank = MetricCS::new();
        blank_circuit
            .synthesize(&mut cs_blank)
            .expect("failed to synthesize");

        let a = cs_blank.pretty_print_list();

        for (circuit1, _inputs) in circuits.into_iter() {
            let mut cs1 = TestConstraintSystem::new();
            circuit1.synthesize(&mut cs1).expect("failed to synthesize");
            let b = cs1.pretty_print_list();

            for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
                assert_eq!(a, b, "failed at chunk {}", i);
            }
        }
    }

    {
        let circuits =
            FallbackPoStCompound::circuit_for_test_all(&pub_params, &pub_inputs, &priv_inputs)
                .unwrap();

        for (circuit, inputs) in circuits.into_iter() {
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
    }

    let blank_groth_params =
        FallbackPoStCompound::<Tree>::groth_params(Some(rng), &pub_params.vanilla_params)
            .expect("failed to generate groth params");

    let proof =
        FallbackPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &blank_groth_params)
            .expect("failed while proving");

    let verified = FallbackPoStCompound::verify(
        &pub_params,
        &pub_inputs,
        &proof,
        &ChallengeRequirements {
            minimum_challenge_count: total_sector_count * challenge_count,
        },
    )
    .expect("failed while verifying");

    assert!(verified);
}
