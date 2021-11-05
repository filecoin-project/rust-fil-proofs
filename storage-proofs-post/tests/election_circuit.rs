use std::collections::BTreeMap;
use std::marker::PhantomData;

use bellperson::{
    bls::{Bls12, Fr},
    util_cs::test_cs::TestConstraintSystem,
    Circuit,
};
use ff::Field;
use filecoin_hashers::{poseidon::PoseidonHasher, Domain, HashFunction, Hasher};
use generic_array::typenum::{U0, U8};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    compound_proof::CompoundProof,
    merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    proof::ProofScheme,
    sector::SectorId,
    util::NODE_SIZE,
    TEST_SEED,
};
use storage_proofs_post::election::{
    self, generate_candidates, ElectionPoSt, ElectionPoStCircuit, ElectionPoStCompound,
};
use tempfile::tempdir;

#[test]
fn test_election_post_circuit_poseidon() {
    test_election_post_circuit::<LCTree<PoseidonHasher, U8, U0, U0>>(22_940);
}

fn test_election_post_circuit<Tree: 'static + MerkleTreeTrait>(expected_constraints: usize) {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = leaves * NODE_SIZE;

    let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
    let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

    let pub_params = election::PublicParams {
        sector_size: sector_size as u64,
        challenge_count: 20,
        challenged_nodes: 1,
    };

    let mut sectors: Vec<SectorId> = Vec::new();
    let mut trees = BTreeMap::new();

    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    for i in 0..5 {
        sectors.push(i.into());
        let (_data, tree) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
        trees.insert(i.into(), tree);
    }

    let candidates =
        generate_candidates::<Tree>(&pub_params, &sectors, &trees, prover_id, randomness).unwrap();

    let candidate = &candidates[0];
    let tree = trees.remove(&candidate.sector_id).unwrap();
    let comm_r_last = tree.root();
    let comm_c = <Tree::Hasher as Hasher>::Domain::random(rng);
    let comm_r = <Tree::Hasher as Hasher>::Function::hash2(&comm_c, &comm_r_last);

    let pub_inputs = election::PublicInputs {
        randomness,
        sector_id: candidate.sector_id,
        prover_id,
        comm_r,
        partial_ticket: candidate.partial_ticket,
        sector_challenge_index: 0,
    };

    let priv_inputs = election::PrivateInputs::<Tree> {
        tree,
        comm_c,
        comm_r_last,
    };

    let proof = ElectionPoSt::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs)
        .expect("proving failed");

    let is_valid = ElectionPoSt::<Tree>::verify(&pub_params, &pub_inputs, &proof)
        .expect("verification failed");
    assert!(is_valid);

    // actual circuit test

    let paths = proof
        .paths()
        .iter()
        .map(|p| {
            p.iter()
                .map(|v| {
                    (
                        v.0.iter().copied().map(Into::into).map(Some).collect(),
                        Some(v.1),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let leafs: Vec<_> = proof.leafs().iter().map(|l| Some((*l).into())).collect();

    let mut cs = TestConstraintSystem::<Bls12>::new();

    let instance = ElectionPoStCircuit::<Tree> {
        leafs,
        paths,
        comm_r: Some(comm_r.into()),
        comm_c: Some(comm_c.into()),
        comm_r_last: Some(comm_r_last.into()),
        partial_ticket: Some(candidate.partial_ticket),
        randomness: Some(randomness.into()),
        prover_id: Some(prover_id.into()),
        sector_id: Some(candidate.sector_id.into()),
        _t: PhantomData,
    };

    instance
        .synthesize(&mut cs)
        .expect("failed to synthesize circuit");

    assert!(cs.is_satisfied(), "constraints not satisfied");

    assert_eq!(cs.num_inputs(), 23, "wrong number of inputs");
    assert_eq!(
        cs.num_constraints(),
        expected_constraints,
        "wrong number of constraints"
    );
    assert_eq!(cs.get_input(0, "ONE"), Fr::one());

    let generated_inputs =
        ElectionPoStCompound::<Tree>::generate_public_inputs(&pub_inputs, &pub_params, None)
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
}
