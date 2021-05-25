use filecoin_hashers::{poseidon::PoseidonHasher, Domain, HashFunction, Hasher};
use generic_array::typenum::{U0, U2, U4, U8};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    error::Error,
    merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    proof::ProofScheme,
    sector::SectorId,
    util::NODE_SIZE,
    TEST_SEED,
};
use storage_proofs_post::fallback::{self, FallbackPoSt, PrivateSector, PublicSector};
use tempfile::tempdir;

#[test]
fn test_fallback_post_poseidon_single_partition_base_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 5, 1, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_single_partition_smaller_base_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(3, 5, 1, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(3, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_base_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_smaller_base_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_single_partition_sub_8_4() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 5, 1, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_single_partition_smaller_sub_8_4() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 5, 1, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_sub_8_4() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(4, 2, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_sub_8_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U8, U0>>(4, 2, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U8, U0>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_smaller_sub_8_4() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 3, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 3, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_smaller_sub_8_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U8, U0>>(5, 3, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U8, U0>>(5, 3, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_single_partition_top_8_4_2() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(5, 5, 1, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(5, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_single_partition_top_8_8_2() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U8, U2>>(5, 5, 1, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U8, U2>>(5, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_single_partition_smaller_top_8_4_2() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 5, 1, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_top_8_4_2() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(4, 2, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_smaller_top_8_4_2() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(5, 3, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(5, 3, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_fallback_post_poseidon_two_partitions_smaller_top_8_8_2() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U8, U2>>(5, 3, 2, ApiVersion::V1_0_0);
    test_fallback_post::<LCTree<PoseidonHasher, U8, U8, U2>>(5, 3, 2, ApiVersion::V1_1_0);
}

fn test_fallback_post<Tree: MerkleTreeTrait>(
    total_sector_count: usize,
    sector_count: usize,
    partitions: usize,
    api_version: ApiVersion,
) where
    Tree::Store: 'static,
{
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves * NODE_SIZE;

    let pub_params = fallback::PublicParams {
        sector_size: sector_size as u64,
        challenge_count: 10,
        sector_count,
        api_version,
    };

    let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
    let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    let mut pub_sectors = Vec::new();
    let mut priv_sectors = Vec::new();

    let trees = (0..total_sector_count)
        .map(|_| generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf())).1)
        .collect::<Vec<_>>();

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

    let pub_inputs = fallback::PublicInputs {
        randomness,
        prover_id,
        sectors: pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors[..],
    };

    let proof = FallbackPoSt::<Tree>::prove_all_partitions(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        partitions,
    )
    .expect("proving failed");

    let is_valid = FallbackPoSt::<Tree>::verify_all_partitions(&pub_params, &pub_inputs, &proof)
        .expect("verification failed");

    assert!(is_valid);
}

#[test]
fn test_invalid_fallback_post_poseidon_single_partition_base_8() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 5, 1, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_single_partition_smaller_base_8() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(3, 5, 1, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(3, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_base_8() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_smaller_base_8() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_single_partition_sub_8_4() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 5, 1, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_single_partition_smaller_sub_8_4() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 5, 1, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_sub_8_4() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(4, 2, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_sub_8_8() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U8, U0>>(4, 2, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U8, U0>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_smaller_sub_8_4() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 3, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(5, 3, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_smaller_sub_8_8() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U8, U0>>(5, 3, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U8, U0>>(5, 3, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_single_partition_top_8_4_2() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(5, 5, 1, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(5, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_single_partition_top_8_8_2() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U8, U2>>(5, 5, 1, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U8, U2>>(5, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_single_partition_smaller_top_8_4_2() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 5, 1, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 5, 1, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_top_8_4_2() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(4, 2, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(4, 2, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_smaller_top_8_4_2() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(5, 3, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(5, 3, 2, ApiVersion::V1_1_0);
}

#[test]
fn test_invalid_fallback_post_poseidon_two_partitions_smaller_top_8_8_2() {
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U8, U2>>(5, 3, 2, ApiVersion::V1_0_0);
    test_invalid_fallback_post::<LCTree<PoseidonHasher, U8, U8, U2>>(5, 3, 2, ApiVersion::V1_1_0);
}

fn test_invalid_fallback_post<Tree: MerkleTreeTrait>(
    total_sector_count: usize,
    sector_count: usize,
    partitions: usize,
    api_version: ApiVersion,
) where
    Tree::Store: 'static,
{
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves * NODE_SIZE;

    let pub_params = fallback::PublicParams {
        sector_size: sector_size as u64,
        challenge_count: 10,
        sector_count,
        api_version,
    };

    let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
    let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    let mut pub_sectors = Vec::new();
    let mut priv_sectors = Vec::new();

    let mut trees = Vec::new();

    let mut faulty_sectors = Vec::<SectorId>::new();

    for _i in 0..total_sector_count {
        let (_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        trees.push(tree);
    }

    let faulty_denominator = 3;

    let (_data, wrong_tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

    for (i, tree) in trees.iter().enumerate() {
        let make_faulty = i % faulty_denominator == 0;

        let comm_c = <Tree::Hasher as Hasher>::Domain::random(rng);
        let comm_r_last = tree.root();

        priv_sectors.push(PrivateSector {
            tree: if make_faulty { &wrong_tree } else { tree },
            comm_c,
            comm_r_last,
        });

        let comm_r = <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);

        if make_faulty {
            faulty_sectors.push((i as u64).into());
        }

        pub_sectors.push(PublicSector {
            id: (i as u64).into(),
            comm_r,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness,
        prover_id,
        sectors: pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors[..],
    };

    let proof = FallbackPoSt::<Tree>::prove_all_partitions(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        partitions,
    );

    match proof {
        Ok(proof) => {
            let is_valid =
                FallbackPoSt::<Tree>::verify_all_partitions(&pub_params, &pub_inputs, &proof)
                    .expect("verification failed");
            assert!(!is_valid, "PoSt returned a valid proof with invalid input");
        }
        Err(e) => match e.downcast::<Error>() {
            Err(_) => panic!("failed to downcast to Error"),
            Ok(Error::FaultySectors(sector_ids)) => assert_eq!(faulty_sectors, sector_ids),
            Ok(_) => panic!("PoSt failed to return FaultySectors error."),
        },
    };
}
