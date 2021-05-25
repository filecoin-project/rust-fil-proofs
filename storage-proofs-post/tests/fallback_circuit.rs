use bellperson::{
    bls::{Bls12, Fr},
    util_cs::{bench_cs::BenchCS, test_cs::TestConstraintSystem},
    Circuit,
};
use ff::Field;
use filecoin_hashers::{poseidon::PoseidonHasher, Domain, HashFunction, Hasher};
use generic_array::typenum::{U0, U2, U4, U8};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    compound_proof::CompoundProof,
    error::Result,
    merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait, OctMerkleTree},
    proof::ProofScheme,
    util::NODE_SIZE,
    TEST_SEED,
};
use storage_proofs_post::fallback::{
    self, FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound, PrivateSector, PublicSector,
    Sector,
};
use tempfile::tempdir;

#[test]
fn test_fallback_post_circuit_poseidon_single_partition_base_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(3, 3, 1, 19, 16_869);
}

#[test]
fn test_fallback_post_circuit_poseidon_single_partition_sub_8_4() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U0>>(3, 3, 1, 19, 22_674);
}

#[test]
fn test_fallback_post_circuit_poseidon_single_partition_top_8_4_2() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U4, U2>>(3, 3, 1, 19, 27_384);
}

#[test]
fn test_fallback_post_circuit_poseidon_two_partitions_base_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(4, 2, 2, 13, 11_246);
}

#[test]
fn test_fallback_post_circuit_poseidon_single_partition_smaller_base_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(2, 3, 1, 19, 16_869);
}

#[test]
fn test_fallback_post_circuit_poseidon_two_partitions_smaller_base_8() {
    test_fallback_post::<LCTree<PoseidonHasher, U8, U0, U0>>(5, 3, 2, 19, 16_869);
}

fn test_fallback_post<Tree: 'static + MerkleTreeTrait>(
    total_sector_count: usize,
    sector_count: usize,
    partitions: usize,
    expected_num_inputs: usize,
    expected_constraints: usize,
) where
    Tree::Store: 'static,
{
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves * NODE_SIZE;
    let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
    let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

    let pub_params = fallback::PublicParams {
        sector_size: sector_size as u64,
        challenge_count: 5,
        sector_count,
        api_version: ApiVersion::V1_1_0,
    };

    let temp_dir = tempdir().expect("tempdir failure");
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

    let pub_inputs = fallback::PublicInputs {
        randomness,
        prover_id,
        sectors: pub_sectors.clone(),
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let proofs = FallbackPoSt::<Tree>::prove_all_partitions(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        partitions,
    )
    .expect("proving failed");
    assert_eq!(proofs.len(), partitions);

    let is_valid = FallbackPoSt::<Tree>::verify_all_partitions(&pub_params, &pub_inputs, &proofs)
        .expect("verification failed");
    assert!(is_valid);

    // actual circuit test

    for (j, proof) in proofs.iter().enumerate() {
        // iterates over each partition
        let circuit_sectors = proof
            .sectors
            .iter()
            .enumerate()
            .map(|(i, proof)| {
                // index into sectors by the correct offset
                let i = j * sector_count + i;

                if i < pub_sectors.len() {
                    Sector::circuit(&pub_sectors[i], proof)
                } else {
                    // duplicated last one
                    let k = pub_sectors.len() - 1;
                    Sector::circuit(&pub_sectors[k], proof)
                }
            })
            .collect::<Result<_>>()
            .expect("circuit sectors failure");

        let mut cs = TestConstraintSystem::<Bls12>::new();

        let instance = FallbackPoStCircuit::<Tree> {
            sectors: circuit_sectors,
            prover_id: Some(prover_id.into()),
        };

        instance
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(
            cs.num_inputs(),
            expected_num_inputs,
            "wrong number of inputs"
        );
        assert_eq!(
            cs.num_constraints(),
            expected_constraints,
            "wrong number of constraints"
        );
        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        let generated_inputs =
            FallbackPoStCompound::<Tree>::generate_public_inputs(&pub_inputs, &pub_params, Some(j))
                .expect("generate_public_inputs failure");
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

        assert!(
            cs.verify(&generated_inputs),
            "verification failed with TestContraintSystem and generated inputs"
        );
    }
}

#[test]
#[ignore]
fn test_fallback_post_circuit_poseidon_base_8_bench_cs() {
    let params = fallback::SetupParams {
        sector_size: (1024 * 1024 * 1024) as u64 * 32_u64,
        challenge_count: 10,
        sector_count: 5,
        api_version: ApiVersion::V1_1_0,
    };

    let pp = FallbackPoSt::<OctMerkleTree<PoseidonHasher>>::setup(&params)
        .expect("fallback post setup failure");

    let mut cs = BenchCS::<Bls12>::new();
    FallbackPoStCompound::<OctMerkleTree<PoseidonHasher>>::blank_circuit(&pp)
        .synthesize(&mut cs)
        .expect("blank circuit failure");

    assert_eq!(cs.num_constraints(), 266_665);
}
