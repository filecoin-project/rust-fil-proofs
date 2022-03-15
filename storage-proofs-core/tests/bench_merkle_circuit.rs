#![allow(unused_imports)]

use std::time::Instant;

use bellperson::{util_cs::test_cs::TestConstraintSystem, Circuit, ConstraintSystem};
use blstrs::Scalar as Fr;
use filecoin_hashers::{
    blake2s::Blake2sHasher, poseidon::PoseidonHasher, sha256::Sha256Hasher, Hasher,
};
use generic_array::typenum::{Unsigned, U0, U2, U4, U8};
use merkletree::store::VecStore;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    gadgets::por::PoRCircuit,
    merkle::{generate_tree, MerkleTreeTrait, MerkleTreeWrapper, ResTree},
    TEST_SEED,
};

#[test]
fn bench_merkle_circuit_challenges() {
    type H = PoseidonHasher;
    type Tree = MerkleTreeWrapper<PoseidonHasher, VecStore<<H as Hasher>::Domain>, U2, U0, U0>;

    let num_leafs = 8;
    // Each "inner" vector specifies the Merkle challenges verified by a single snark.
    let challenges_per_snark = vec![
        vec![0],
        vec![1, 2],
    ];

    let mut rng = XorShiftRng::from_seed(TEST_SEED);
    let (_leafs_data, tree) = generate_tree::<Tree, _>(&mut rng, num_leafs, None);

    for snark_challenges in challenges_per_snark {
        println!("\ngenerating constraint-system for Merkle challenges: {:?}", snark_challenges);
        let mut cs = TestConstraintSystem::new();
        let mut pub_inputs = vec![];

        for c in snark_challenges {
            println!("\tchallenge: {}", c);
            let merkle_proof = tree.gen_proof(c).expect("failed to generate Merkle proof");
            let circ = PoRCircuit::<ResTree<Tree>>::new(merkle_proof, false);
            pub_inputs.push(Fr::from(c as u64));
            pub_inputs.push(tree.root().into());

            let start = Instant::now();
            circ.synthesize(&mut cs.namespace(|| format!("challenge {} mekle proof", c)))
                .expect("failed to synthesize circuit");
            let synth_time = start.elapsed().as_secs_f32();
            println!("\t\tsynthesis time for challenge's Merkle proof: {}", synth_time);
        }

        let start = Instant::now();
        let is_sat = cs.is_satisfied();
        let sat_time = start.elapsed().as_secs_f32();
        assert!(is_sat, "constraint system is not satisfied");

        let start = Instant::now();
        let is_valid = cs.verify(&pub_inputs);
        let verify_time = start.elapsed().as_secs_f32();
        assert!(is_valid, "constraint system is not valid for public-inputs");

        println!("\tconstraint-system sat time: {}", sat_time);
        println!("\tconstraint-system verify time: {}", verify_time);
        println!("\n");
    }
}
