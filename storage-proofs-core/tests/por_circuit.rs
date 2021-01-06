use bellperson::{
    bls::{Bls12, Fr},
    gadgets::{boolean::AllocatedBit, multipack, num::AllocatedNum},
    util_cs::test_cs::TestConstraintSystem,
    Circuit, ConstraintSystem,
};
use ff::Field;
use filecoin_hashers::{
    blake2s::Blake2sHasher, poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, Hasher,
};
use fr32::{bytes_into_fr, fr_into_bytes};
use generic_array::typenum::{Unsigned, U0, U2, U4, U8};
use merkletree::store::VecStore;
use pretty_assertions::assert_eq;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    compound_proof::CompoundProof,
    gadgets::por::{
        challenge_into_auth_path_bits, por_no_challenge_input, PoRCircuit, PoRCompound,
    },
    merkle::{
        create_base_merkle_tree, generate_tree, get_base_tree_count, MerkleProofTrait,
        MerkleTreeTrait, MerkleTreeWrapper, ResTree,
    },
    por::{self, PoR},
    proof::ProofScheme,
    util::data_at_node,
    TEST_SEED,
};

type TreeBase<H, A> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, U0, U0>;
type TreeSub<H, A, B> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, B, U0>;
type TreeTop<H, A, B, C> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, B, C>;

#[test]
fn test_por_circuit_blake2s_base_2() {
    test_por_circuit::<TreeBase<Blake2sHasher, U2>>(3, 129_135);
}

#[test]
fn test_por_circuit_sha256_base_2() {
    test_por_circuit::<TreeBase<Sha256Hasher, U2>>(3, 272_295);
}

#[test]
fn test_por_circuit_poseidon_base_2() {
    test_por_circuit::<TreeBase<PoseidonHasher, U2>>(3, 1_887);
}

#[test]
fn test_por_circuit_blake2s_base_4() {
    test_por_circuit::<TreeBase<Blake2sHasher, U4>>(3, 130_296);
}

#[test]
fn test_por_circuit_sha256_base_4() {
    test_por_circuit::<TreeBase<Sha256Hasher, U4>>(3, 216_258);
}

#[test]
fn test_por_circuit_poseidon_base_4() {
    test_por_circuit::<TreeBase<PoseidonHasher, U4>>(3, 1_164);
}

#[test]
fn test_por_circuit_blake2s_base_8() {
    test_por_circuit::<TreeBase<Blake2sHasher, U8>>(3, 174_503);
}

#[test]
fn test_por_circuit_sha256_base_8() {
    test_por_circuit::<TreeBase<Sha256Hasher, U8>>(3, 250_987);
}

#[test]
fn test_por_circuit_poseidon_base_8() {
    test_por_circuit::<TreeBase<PoseidonHasher, U8>>(3, 1_063);
}

#[test]
fn test_por_circuit_poseidon_sub_8_2() {
    test_por_circuit::<TreeSub<PoseidonHasher, U8, U2>>(3, 1_377);
}

#[test]
fn test_por_circuit_poseidon_top_8_4_2() {
    test_por_circuit::<TreeTop<PoseidonHasher, U8, U4, U2>>(3, 1_764);
}

#[test]
fn test_por_circuit_poseidon_sub_8_8() {
    // This is the shape we want for 32GiB sectors.
    test_por_circuit::<TreeSub<PoseidonHasher, U8, U8>>(3, 1_593);
}
#[test]
fn test_por_circuit_poseidon_top_8_8_2() {
    // This is the shape we want for 64GiB secotrs.
    test_por_circuit::<TreeTop<PoseidonHasher, U8, U8, U2>>(3, 1_907);
}

#[test]
fn test_por_circuit_poseidon_top_8_2_4() {
    // We can handle top-heavy trees with a non-zero subtree arity.
    // These should never be produced, though.
    test_por_circuit::<TreeTop<PoseidonHasher, U8, U2, U4>>(3, 1_764);
}

fn test_por_circuit<Tree: 'static + MerkleTreeTrait>(num_inputs: usize, num_constraints: usize) {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    // Ensure arity will evenly fill tree.
    let leaves = 64 * get_base_tree_count::<Tree>();

    // -- Basic Setup
    let (data, tree) = generate_tree::<Tree, _>(rng, leaves, None);

    for i in 0..leaves {
        //println!("challenge: {}, ({})", i, leaves);

        // -- PoR
        let pub_params = por::PublicParams {
            leaves,
            private: false,
        };
        let pub_inputs = por::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
            challenge: i,
            commitment: Some(tree.root()),
        };
        let leaf =
            data_at_node(data.as_slice(), pub_inputs.challenge).expect("data_at_node failure");
        let leaf_element =
            <Tree::Hasher as Hasher>::Domain::try_from_bytes(leaf).expect("try_from_bytes failure");
        let priv_inputs = por::PrivateInputs::<ResTree<Tree>>::new(leaf_element, &tree);
        let p = tree.gen_proof(i).expect("gen_proof failure");
        assert!(p.verify());

        // create a non circuit proof
        let proof = PoR::<ResTree<Tree>>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        // make sure it verifies
        let is_valid = PoR::<ResTree<Tree>>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");
        assert!(is_valid, "failed to verify por proof");

        // -- Circuit

        let mut cs = TestConstraintSystem::<Bls12>::new();

        // Root is public input.
        let por = PoRCircuit::<ResTree<Tree>>::new(proof.proof, false);
        por.synthesize(&mut cs).expect("circuit synthesis failed");
        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), num_inputs, "wrong number of inputs");
        assert_eq!(
            cs.num_constraints(),
            num_constraints,
            "wrong number of constraints"
        );

        let generated_inputs =
            PoRCompound::<ResTree<Tree>>::generate_public_inputs(&pub_inputs, &pub_params, None)
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

        assert!(cs.verify(&generated_inputs), "failed to verify inputs");
    }
}

#[test]
fn test_por_circuit_poseidon_base_2_private_root() {
    test_por_circuit_private_root::<TreeBase<PoseidonHasher, U2>>(1_886);
}

#[test]
fn test_por_circuit_poseidon_base_4_private_root() {
    test_por_circuit_private_root::<TreeBase<PoseidonHasher, U4>>(1_163);
}

#[test]
fn test_por_circuit_poseidon_base_8_private_root() {
    test_por_circuit_private_root::<TreeBase<PoseidonHasher, U8>>(1_062);
}

fn test_por_circuit_private_root<Tree: MerkleTreeTrait>(num_constraints: usize) {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    for i in 0..leaves {
        // -- Basic Setup

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let tree = create_base_merkle_tree::<Tree>(None, leaves, data.as_slice())
            .expect("create_base_merkle_tree failure");

        // -- PoR

        let pub_params = por::PublicParams {
            leaves,
            private: true,
        };
        let pub_inputs = por::PublicInputs {
            challenge: i,
            commitment: None,
        };

        let priv_inputs = por::PrivateInputs::<Tree>::new(
            bytes_into_fr(
                data_at_node(data.as_slice(), pub_inputs.challenge).expect("data_at_node failure"),
            )
            .expect("bytes_into_fr failure")
            .into(),
            &tree,
        );

        // create a non circuit proof
        let proof =
            PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

        // make sure it verifies
        let is_valid =
            PoR::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
        assert!(is_valid, "failed to verify por proof");

        // -- Circuit

        let mut cs = TestConstraintSystem::<Bls12>::new();

        // Root is private input.
        let por = PoRCircuit::<Tree>::new(proof.proof, true);
        por.synthesize(&mut cs).expect("circuit synthesis failed");
        assert!(cs.is_satisfied(), "constraints not satisfied");

        assert_eq!(cs.num_inputs(), 2, "wrong number of inputs");
        assert_eq!(
            cs.num_constraints(),
            num_constraints,
            "wrong number of constraints"
        );

        let auth_path_bits = challenge_into_auth_path_bits(pub_inputs.challenge, pub_params.leaves);
        let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

        let mut expected_inputs = Vec::new();
        expected_inputs.extend(packed_auth_path);

        assert_eq!(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

        assert_eq!(
            cs.get_input(1, "path/input 0"),
            expected_inputs[0],
            "wrong packed_auth_path"
        );

        assert!(cs.is_satisfied(), "constraints are not all satisfied");
        assert!(cs.verify(&expected_inputs), "failed to verify inputs");
    }
}

#[test]
fn test_por_no_challenge_input() {
    type Arity = U8;
    type Tree = TreeBase<PoseidonHasher, Arity>;

    // == Setup
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let height = 3;
    let n_leaves = Arity::to_usize() << height;

    let data: Vec<u8> = (0..n_leaves)
        .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
        .collect();

    let tree = create_base_merkle_tree::<Tree>(None, n_leaves, &data)
        .expect("create_base_merkle_tree failure");
    let root = tree.root();

    let challenge = rng.gen::<usize>() % n_leaves;
    let leaf_bytes = data_at_node(&data, challenge).expect("data_at_node failure");
    let leaf = bytes_into_fr(leaf_bytes).expect("bytes_into_fr failure");

    // == Vanilla PoR proof
    let proof = {
        use por::{PoR, PrivateInputs, PublicInputs, PublicParams};
        let pub_params = PublicParams {
            leaves: n_leaves,
            private: false,
        };
        let pub_inputs = PublicInputs {
            challenge,
            commitment: None,
        };
        let priv_inputs = PrivateInputs {
            leaf: leaf.into(),
            tree: &tree,
        };
        let proof =
            PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");
        let is_valid =
            PoR::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");
        assert!(is_valid, "failed to verify por proof");
        proof.proof
    };

    // == Test PoR gadget
    let mut cs = TestConstraintSystem::<Bls12>::new();

    let challenge_bit_len = n_leaves.trailing_zeros() as usize;
    let challenge: Vec<AllocatedBit> = (0..challenge_bit_len)
        .map(|i| {
            AllocatedBit::alloc(
                cs.namespace(|| format!("challenge bit {}", i)),
                Some((challenge >> i) & 1 == 1),
            )
            .expect("failed to allocate challenge bit")
        })
        .collect();

    let leaf = AllocatedNum::alloc(cs.namespace(|| "leaf".to_string()), || Ok(leaf))
        .expect("failed to allocate leaf");

    let path_values: Vec<Vec<AllocatedNum<Bls12>>> = proof
        .path()
        .iter()
        .enumerate()
        .map(|(height, (siblings, _insert_index))| {
            siblings
                .iter()
                .enumerate()
                .map(|(sib_index, &sib)| {
                    AllocatedNum::alloc(
                        cs.namespace(|| format!("sib {}, height {}", sib_index, height)),
                        || Ok(sib.into()),
                    )
                    .expect("failed to allocate sibling")
                })
                .collect()
        })
        .collect();

    let root = AllocatedNum::alloc(cs.namespace(|| "root".to_string()), || Ok(root.into()))
        .expect("failed to allocate root");

    por_no_challenge_input::<Tree, _>(&mut cs, challenge, leaf, path_values, root)
        .expect("por gadget failed");

    assert!(cs.is_satisfied());
    let public_inputs = vec![];
    assert!(cs.verify(&public_inputs));
}
