use std::collections::BTreeMap;

use filecoin_hashers::{
    blake2s::Blake2sHasher, poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, HashFunction,
    Hasher,
};
use generic_array::typenum::{U0, U2, U8};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    proof::ProofScheme,
    sector::OrderedSectorSet,
    TEST_SEED,
};
use storage_proofs_post::rational::{self, derive_challenges, RationalPoSt};
use tempfile::tempdir;

#[test]
fn test_rational_post_sha256_base_8() {
    test_rational_post::<LCTree<Sha256Hasher, U8, U0, U0>>();
}

#[test]
fn test_rational_post_blake2s_base_8() {
    test_rational_post::<LCTree<Blake2sHasher, U8, U0, U0>>();
}

#[test]
fn test_rational_post_poseidon_base_8() {
    test_rational_post::<LCTree<PoseidonHasher, U8, U0, U0>>();
}

#[test]
fn test_rational_post_poseidon_sub_8_8() {
    test_rational_post::<LCTree<PoseidonHasher, U8, U8, U0>>();
}

#[test]
fn test_rational_post_poseidon_top_8_8_2() {
    test_rational_post::<LCTree<PoseidonHasher, U8, U8, U2>>();
}

fn test_rational_post<Tree: MerkleTreeTrait>()
where
    Tree::Store: 'static,
{
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves as u64 * 32;
    let challenges_count = 8;

    let pub_params = rational::PublicParams {
        sector_size,
        challenges_count,
    };

    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    let (_data1, tree1) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    let (_data2, tree2) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

    let seed = (0..leaves).map(|_| rng.gen()).collect::<Vec<u8>>();
    let mut faults = OrderedSectorSet::new();
    faults.insert(139.into());
    faults.insert(1.into());
    faults.insert(32.into());

    let mut sectors = OrderedSectorSet::new();
    sectors.insert(891.into());
    sectors.insert(139.into());
    sectors.insert(32.into());
    sectors.insert(1.into());

    let mut trees = BTreeMap::new();
    trees.insert(139.into(), &tree1); // faulty with tree
    trees.insert(891.into(), &tree2);
    // other two faults don't have a tree available

    let challenges =
        derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();

    // the only valid sector to challenge is 891
    assert!(
        challenges.iter().all(|c| c.sector == 891.into()),
        "invalid challenge generated"
    );

    let comm_r_lasts = challenges
        .iter()
        .map(|c| trees.get(&c.sector).unwrap().root())
        .collect::<Vec<_>>();

    let comm_cs: Vec<<Tree::Hasher as Hasher>::Domain> = challenges
        .iter()
        .map(|_c| <Tree::Hasher as Hasher>::Domain::random(rng))
        .collect();

    let comm_rs: Vec<<Tree::Hasher as Hasher>::Domain> = comm_cs
        .iter()
        .zip(comm_r_lasts.iter())
        .map(|(comm_c, comm_r_last)| <Tree::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last))
        .collect();

    let pub_inputs = rational::PublicInputs {
        challenges,
        comm_rs,
        faults,
    };

    let priv_inputs = rational::PrivateInputs::<Tree> {
        trees: &trees,
        comm_cs: &comm_cs,
        comm_r_lasts: &comm_r_lasts,
    };

    let proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
        .expect("proving failed");

    let is_valid = RationalPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof)
        .expect("verification failed");

    assert!(is_valid);
}

#[test]
fn test_rational_post_validates_challenge_sha256_base_8() {
    test_rational_post_validates_challenge::<LCTree<Sha256Hasher, U8, U0, U0>>();
}

#[test]
fn test_rational_post_validates_challenge_blake2s_base_8() {
    test_rational_post_validates_challenge::<LCTree<Blake2sHasher, U8, U0, U0>>();
}

#[test]
fn test_rational_post_validates_challenge_poseidon_base_8() {
    test_rational_post_validates_challenge::<LCTree<PoseidonHasher, U8, U0, U0>>();
}

#[test]
fn test_rational_post_validates_challenge_poseidon_sub_8_8() {
    test_rational_post_validates_challenge::<LCTree<PoseidonHasher, U8, U8, U0>>();
}

#[test]
fn test_rational_post_validates_challenge_poseidon_top_8_8_2() {
    test_rational_post_validates_challenge::<LCTree<PoseidonHasher, U8, U8, U2>>();
}

fn test_rational_post_validates_challenge<Tree: 'static + MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves as u64 * 32;
    let challenges_count = 2;

    let pub_params = rational::PublicParams {
        sector_size,
        challenges_count,
    };

    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    let (_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    let seed = (0..leaves).map(|_| rng.gen()).collect::<Vec<u8>>();
    let mut faults = OrderedSectorSet::new();
    faults.insert(1.into());
    let mut sectors = OrderedSectorSet::new();
    sectors.insert(0.into());
    sectors.insert(1.into());

    let mut trees = BTreeMap::new();
    trees.insert(0.into(), &tree);

    let challenges =
        derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
    let comm_r_lasts = challenges
        .iter()
        .map(|c| trees.get(&c.sector).unwrap().root())
        .collect::<Vec<_>>();

    let comm_cs: Vec<<Tree::Hasher as Hasher>::Domain> = challenges
        .iter()
        .map(|_c| <Tree::Hasher as Hasher>::Domain::random(rng))
        .collect();

    let comm_rs: Vec<<Tree::Hasher as Hasher>::Domain> = comm_cs
        .iter()
        .zip(comm_r_lasts.iter())
        .map(|(comm_c, comm_r_last)| <Tree::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last))
        .collect();

    let pub_inputs = rational::PublicInputs {
        challenges,
        faults: faults.clone(),
        comm_rs,
    };

    let priv_inputs = rational::PrivateInputs::<Tree> {
        trees: &trees,
        comm_cs: &comm_cs,
        comm_r_lasts: &comm_r_lasts,
    };

    let proof = RationalPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
        .expect("proving failed");

    let seed = (0..leaves).map(|_| rng.gen()).collect::<Vec<u8>>();
    let challenges =
        derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
    let comm_r_lasts = challenges.iter().map(|_c| tree.root()).collect::<Vec<_>>();

    let comm_cs: Vec<<Tree::Hasher as Hasher>::Domain> = challenges
        .iter()
        .map(|_c| <Tree::Hasher as Hasher>::Domain::random(rng))
        .collect();

    let comm_rs: Vec<<Tree::Hasher as Hasher>::Domain> = comm_cs
        .iter()
        .zip(comm_r_lasts.iter())
        .map(|(comm_c, comm_r_last)| <Tree::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last))
        .collect();

    let different_pub_inputs = rational::PublicInputs {
        challenges,
        faults,
        comm_rs,
    };

    let verified = RationalPoSt::<Tree>::verify(&pub_params, &different_pub_inputs, &proof)
        .expect("verification failed");

    // A proof created with a the wrong challenge not be verified!
    assert!(!verified);
}
