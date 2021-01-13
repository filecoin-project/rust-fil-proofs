use std::collections::BTreeMap;

use filecoin_hashers::{poseidon::PoseidonHasher, Domain, HashFunction, Hasher};
use generic_array::typenum::{U0, U2, U8};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    proof::ProofScheme,
    sector::SectorId,
    util::NODE_SIZE,
    TEST_SEED,
};
use storage_proofs_post::election::{
    generate_candidates, ElectionPoSt, PrivateInputs, PublicInputs, PublicParams,
};
use tempfile::tempdir;

#[test]
fn test_election_post_poseidon_base_8() {
    test_election_post::<LCTree<PoseidonHasher, U8, U0, U0>>();
}

#[test]
fn test_election_post_poseidon_sub_8_8() {
    test_election_post::<LCTree<PoseidonHasher, U8, U8, U0>>();
}

#[test]
fn test_election_post_poseidon_top_8_8_2() {
    test_election_post::<LCTree<PoseidonHasher, U8, U8, U2>>();
}

fn test_election_post<Tree: 'static + MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves * NODE_SIZE;

    let pub_params = PublicParams {
        sector_size: sector_size as u64,
        challenge_count: 40,
        challenged_nodes: 1,
    };

    let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
    let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

    let mut sectors: Vec<SectorId> = Vec::new();
    let mut trees = BTreeMap::new();

    let temp_dir = tempdir().expect("tempdir failure");
    let temp_path = temp_dir.path();

    for i in 0..5 {
        sectors.push(i.into());
        let (_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        trees.insert(i.into(), tree);
    }

    let candidates =
        generate_candidates::<Tree>(&pub_params, &sectors, &trees, prover_id, randomness)
            .expect("generate candidates failure");

    let candidate = &candidates[0];
    let tree = trees
        .remove(&candidate.sector_id)
        .expect("trees.remove failure");
    let comm_r_last = tree.root();
    let comm_c = <Tree::Hasher as Hasher>::Domain::random(rng);
    let comm_r = <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);

    let pub_inputs = PublicInputs {
        randomness,
        sector_id: candidate.sector_id,
        prover_id,
        comm_r,
        partial_ticket: candidate.partial_ticket,
        sector_challenge_index: 0,
    };

    let priv_inputs = PrivateInputs::<Tree> {
        tree,
        comm_c,
        comm_r_last,
    };

    let proof = ElectionPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
        .expect("proving failed");

    let is_valid = ElectionPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof)
        .expect("verification failed");

    assert!(is_valid);
}
