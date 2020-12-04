use bellperson::{
    bls::Fr,
    util_cs::{metric_cs::MetricCS, test_cs::TestConstraintSystem},
    Circuit,
};
use ff::Field;
use filecoin_hashers::{poseidon::PoseidonHasher, Hasher};
use fr32::{bytes_into_fr, fr_into_bytes};
use generic_array::typenum::{U0, U2, U4, U8};
use merkletree::store::VecStore;
use pretty_assertions::assert_eq;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    gadgets::por::PoRCompound,
    merkle::{
        create_base_merkle_tree, generate_tree, get_base_tree_count, MerkleTreeTrait,
        MerkleTreeWrapper, ResTree,
    },
    por,
    proof::NoRequirements,
    util::data_at_node,
    TEST_SEED,
};

type TreeBase<H, A> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, U0, U0>;
type TreeSub<H, A, B> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, B, U0>;
type TreeTop<H, A, B, C> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, B, C>;

#[test]
#[ignore]
fn test_por_compound_poseidon_base_8() {
    por_compound::<TreeBase<PoseidonHasher, U8>>();
}

fn por_compound<Tree: 'static + MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();

    let data: Vec<u8> = (0..leaves)
        .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
        .collect();
    let tree = create_base_merkle_tree::<Tree>(None, leaves, data.as_slice())
        .expect("create_base_merkle_tree failure");

    let public_inputs = por::PublicInputs {
        challenge: 2,
        commitment: Some(tree.root()),
    };

    let setup_params = compound_proof::SetupParams {
        vanilla_params: por::SetupParams {
            leaves,
            private: false,
        },
        partitions: None,
        priority: false,
    };
    let public_params = PoRCompound::<Tree>::setup(&setup_params).expect("setup failed");

    let private_inputs = por::PrivateInputs::<Tree>::new(
        bytes_into_fr(
            data_at_node(data.as_slice(), public_inputs.challenge).expect("bytes_into_fr failure"),
        )
        .expect("failed to create Fr from node data")
        .into(),
        &tree,
    );

    let gparams = PoRCompound::<Tree>::groth_params(Some(rng), &public_params.vanilla_params)
        .expect("failed to generate groth params");

    let proof =
        PoRCompound::<Tree>::prove(&public_params, &public_inputs, &private_inputs, &gparams)
            .expect("failed while proving");

    let verified =
        PoRCompound::<Tree>::verify(&public_params, &public_inputs, &proof, &NoRequirements)
            .expect("failed while verifying");
    assert!(verified);

    let (circuit, inputs) =
        PoRCompound::<Tree>::circuit_for_test(&public_params, &public_inputs, &private_inputs)
            .expect("circuit_for_test failure");

    let mut cs = TestConstraintSystem::new();

    circuit.synthesize(&mut cs).expect("failed to synthesize");
    assert!(cs.is_satisfied());
    assert!(cs.verify(&inputs));
}

#[ignore]
#[test]
fn test_por_compound_poseidon_base_2_private_root() {
    por_compound_private_root::<TreeBase<PoseidonHasher, U2>>();
}

#[ignore]
#[test]
fn test_por_compound_poseidon_base_4_private_root() {
    por_compound_private_root::<TreeBase<PoseidonHasher, U4>>();
}

#[ignore]
#[test]
fn test_por_compound_poseidon_sub_8_2_private_root() {
    por_compound_private_root::<TreeSub<PoseidonHasher, U8, U2>>();
}

#[ignore]
#[test]
fn test_por_compound_poseidon_top_8_4_2_private_root() {
    por_compound_private_root::<TreeTop<PoseidonHasher, U8, U4, U2>>();
}

#[ignore]
#[test]
fn test_por_compound_poseidon_sub_8_8_private_root() {
    por_compound_private_root::<TreeSub<PoseidonHasher, U8, U8>>();
}

#[ignore]
#[test]
fn test_por_compound_poseidon_top_8_8_2_private_root() {
    por_compound_private_root::<TreeTop<PoseidonHasher, U8, U8, U2>>();
}

#[ignore]
#[test]
fn test_por_compound_poseidon_top_8_2_4_private_root() {
    por_compound_private_root::<TreeTop<PoseidonHasher, U8, U2, U4>>();
}

fn por_compound_private_root<Tree: 'static + MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    // Ensure arity will evenly fill tree.
    let leaves = 64 * get_base_tree_count::<Tree>();

    // -- Basic Setup
    let (data, tree) = generate_tree::<Tree, _>(rng, leaves, None);

    for i in 0..3 {
        let public_inputs = por::PublicInputs {
            challenge: i,
            commitment: None,
        };

        let setup_params = compound_proof::SetupParams {
            vanilla_params: por::SetupParams {
                leaves,
                private: true,
            },
            partitions: None,
            priority: false,
        };
        let public_params =
            PoRCompound::<ResTree<Tree>>::setup(&setup_params).expect("setup failed");

        let private_inputs = por::PrivateInputs::<ResTree<Tree>>::new(
            bytes_into_fr(
                data_at_node(data.as_slice(), public_inputs.challenge)
                    .expect("data_at_node failure"),
            )
            .expect("failed to create Fr from node data")
            .into(),
            &tree,
        );

        {
            let (circuit, inputs) =
                PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                    .expect("circuit_for_test");

            let mut cs = TestConstraintSystem::new();

            circuit.synthesize(&mut cs).expect("failed to synthesize");

            if !cs.is_satisfied() {
                panic!(
                    "failed to satisfy: {:?}",
                    cs.which_is_unsatisfied().expect("cs is_satisfied failure")
                );
            }
            assert!(
                cs.verify(&inputs),
                "verification failed with TestContraintSystem and generated inputs"
            );
        }
        // NOTE: This diagnostic code currently fails, even though the proof generated from the blank circuit verifies.
        // Use this to debug differences between blank and regular circuit generation.
        {
            let (circuit1, _inputs) =
                PoRCompound::circuit_for_test(&public_params, &public_inputs, &private_inputs)
                    .expect("circuit_for_test failure");
            let blank_circuit =
                PoRCompound::<ResTree<Tree>>::blank_circuit(&public_params.vanilla_params);

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
            PoRCompound::<ResTree<Tree>>::groth_params(Some(rng), &public_params.vanilla_params)
                .expect("failed to generate groth params");

        let proof = PoRCompound::prove(
            &public_params,
            &public_inputs,
            &private_inputs,
            &blank_groth_params,
        )
        .expect("failed while proving");

        let verified = PoRCompound::verify(&public_params, &public_inputs, &proof, &NoRequirements)
            .expect("failed while verifying");

        assert!(verified);
    }
}
