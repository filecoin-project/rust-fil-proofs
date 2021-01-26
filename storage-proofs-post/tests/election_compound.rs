use std::collections::BTreeMap;

use bellperson::{
    util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem},
    Circuit,
};
use filecoin_hashers::{poseidon::PoseidonHasher, Domain, HashFunction, Hasher};
use generic_array::typenum::{U0, U8};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    merkle::{generate_tree, get_base_tree_count, LCTree, MerkleTreeTrait},
    proof::NoRequirements,
    sector::SectorId,
    util::NODE_SIZE,
    TEST_SEED,
};
use storage_proofs_post::election::{
    generate_candidates, ElectionPoStCompound, PrivateInputs, PublicInputs, SetupParams,
};
use tempfile::tempdir;

#[ignore]
#[test]
fn test_election_post_compound_poseidon() {
    test_election_post_compound::<LCTree<PoseidonHasher, U8, U0, U0>>();
}

fn test_election_post_compound<Tree: 'static + MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    let sector_size = (leaves * NODE_SIZE) as u64;
    let randomness = <Tree::Hasher as Hasher>::Domain::random(rng);
    let prover_id = <Tree::Hasher as Hasher>::Domain::random(rng);

    let setup_params = compound_proof::SetupParams {
        vanilla_params: SetupParams {
            sector_size,
            challenge_count: 20,
            challenged_nodes: 1,
        },
        partitions: None,
        priority: true,
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

    let pub_params = ElectionPoStCompound::<Tree>::setup(&setup_params).expect("setup failed");

    let candidates = generate_candidates::<Tree>(
        &pub_params.vanilla_params,
        &sectors,
        &trees,
        prover_id,
        randomness,
    )
    .unwrap();

    let candidate = &candidates[0];
    let tree = trees.remove(&candidate.sector_id).unwrap();
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

    {
        let (circuit, inputs) =
            ElectionPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs).unwrap();

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
            ElectionPoStCompound::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        let blank_circuit = ElectionPoStCompound::<Tree>::blank_circuit(&pub_params.vanilla_params);

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
    let blank_groth_params =
        ElectionPoStCompound::<Tree>::groth_params(Some(rng), &pub_params.vanilla_params)
            .expect("failed to generate groth params");

    let proof =
        ElectionPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &blank_groth_params)
            .expect("failed while proving");

    let verified = ElectionPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
        .expect("failed while verifying");

    assert!(verified);
}
