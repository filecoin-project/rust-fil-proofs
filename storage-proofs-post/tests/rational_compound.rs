use std::collections::BTreeMap;

use bellperson::{util_cs::test_cs::TestConstraintSystem, Circuit};
use filecoin_hashers::{poseidon::PoseidonHasher, Domain, HashFunction, Hasher};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    merkle::{generate_tree, get_base_tree_count, BinaryMerkleTree, MerkleTreeTrait},
    proof::NoRequirements,
    sector::OrderedSectorSet,
    util::NODE_SIZE,
    TEST_SEED,
};
use storage_proofs_post::rational::{self, derive_challenges, RationalPoStCompound};
use tempfile::tempdir;

#[ignore]
#[test]
fn test_rational_post_compound_poseidon() {
    test_rational_post_compound::<BinaryMerkleTree<PoseidonHasher>>();
}

fn test_rational_post_compound<Tree: 'static + MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 32 * get_base_tree_count::<Tree>();
    let sector_size = (leaves * NODE_SIZE) as u64;
    let challenges_count = 2;

    let setup_params = compound_proof::SetupParams {
        vanilla_params: rational::SetupParams {
            sector_size,
            challenges_count,
        },
        partitions: None,
        priority: true,
    };

    let pub_params = RationalPoStCompound::<Tree>::setup(&setup_params).expect("setup failed");

    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    let (_data1, tree1) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));
    let (_data2, tree2) = generate_tree::<Tree, _>(rng, leaves, Some(temp_path.to_path_buf()));

    let faults = OrderedSectorSet::new();
    let mut sectors = OrderedSectorSet::new();
    sectors.insert(0.into());
    sectors.insert(1.into());

    let seed = (0..leaves).map(|_| rng.gen()).collect::<Vec<u8>>();
    let challenges =
        derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();

    let comm_r_lasts_raw = vec![tree1.root(), tree2.root()];
    let comm_r_lasts: Vec<_> = challenges
        .iter()
        .map(|c| comm_r_lasts_raw[u64::from(c.sector) as usize])
        .collect();

    let comm_cs: Vec<<Tree::Hasher as Hasher>::Domain> = challenges
        .iter()
        .map(|_c| <Tree::Hasher as Hasher>::Domain::random(rng))
        .collect();

    let comm_rs: Vec<_> = comm_cs
        .iter()
        .zip(comm_r_lasts.iter())
        .map(|(comm_c, comm_r_last)| <Tree::Hasher as Hasher>::Function::hash2(comm_c, comm_r_last))
        .collect();

    let pub_inputs = rational::PublicInputs {
        challenges: challenges.clone(),
        faults: faults.clone(),
        comm_rs: comm_rs.clone(),
    };

    let mut trees = BTreeMap::new();
    trees.insert(0.into(), &tree1);
    trees.insert(1.into(), &tree2);

    let priv_inputs = rational::PrivateInputs::<Tree> {
        trees: &trees,
        comm_r_lasts: &comm_r_lasts,
        comm_cs: &comm_cs,
    };

    let gparams = RationalPoStCompound::<Tree>::groth_params(Some(rng), &pub_params.vanilla_params)
        .expect("failed to create groth params");

    let proof =
        RationalPoStCompound::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs, &gparams)
            .expect("proving failed");

    let (circuit, inputs) =
        RationalPoStCompound::<Tree>::circuit_for_test(&pub_params, &pub_inputs, &priv_inputs)
            .unwrap();

    {
        let mut cs = TestConstraintSystem::new();

        circuit.synthesize(&mut cs).expect("failed to synthesize");
        assert!(cs.is_satisfied());
        assert!(cs.verify(&inputs));
    }

    let verified =
        RationalPoStCompound::<Tree>::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)
            .expect("failed while verifying");

    assert!(verified);
}
