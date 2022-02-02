use std::path::Path;

use bellperson::{
    gadgets::{boolean::AllocatedBit, multipack, num::AllocatedNum},
    util_cs::test_cs::TestConstraintSystem,
    Circuit, ConstraintSystem,
};
use blstrs::Scalar as Fr;
use ff::Field;
use filecoin_hashers::{
    blake2s::Blake2sHasher,
    poseidon::{PoseidonDomain, PoseidonHasher},
    sha256::Sha256Hasher,
    Domain, Hasher, PoseidonArity,
};
use fr32::{bytes_into_fr, fr_into_bytes};
use generic_array::typenum::{Unsigned, U0, U2, U4, U8};
use merkletree::store::{StoreConfig, VecStore};
use pretty_assertions::assert_eq;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    compound_proof::CompoundProof,
    gadgets::por::{
        challenge_into_auth_path_bits, por_no_challenge_input, PoRCircuit, PoRCompound,
    },
    merkle::{
        create_base_merkle_tree, generate_tree, get_base_tree_count, DiskTree, MerkleProofTrait,
        MerkleTreeTrait, MerkleTreeWrapper, ResTree,
    },
    por::{self, PoR},
    proof::ProofScheme,
    util::{data_at_node, default_rows_to_discard},
    TEST_SEED,
};
use tempfile::tempdir;

type TreeBase<H, A> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, U0, U0>;
type TreeSub<H, A, B> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, B, U0>;
type TreeTop<H, A, B, C> = MerkleTreeWrapper<H, VecStore<<H as Hasher>::Domain>, A, B, C>;

#[test]
fn test_por_circuit_blake2s_base_2() {
    test_por_circuit::<TreeBase<Blake2sHasher<Fr>, U2>>(3, 129_135);
}

#[test]
fn test_por_circuit_sha256_base_2() {
    test_por_circuit::<TreeBase<Sha256Hasher<Fr>, U2>>(3, 272_295);
}

#[test]
fn test_por_circuit_poseidon_base_2() {
    test_por_circuit::<TreeBase<PoseidonHasher<Fr>, U2>>(3, 1_887);
}

#[test]
fn test_por_circuit_blake2s_base_4() {
    test_por_circuit::<TreeBase<Blake2sHasher<Fr>, U4>>(3, 130_296);
}

#[test]
fn test_por_circuit_sha256_base_4() {
    test_por_circuit::<TreeBase<Sha256Hasher<Fr>, U4>>(3, 216_258);
}

#[test]
fn test_por_circuit_poseidon_base_4() {
    test_por_circuit::<TreeBase<PoseidonHasher<Fr>, U4>>(3, 1_164);
}

#[test]
fn test_por_circuit_blake2s_base_8() {
    test_por_circuit::<TreeBase<Blake2sHasher<Fr>, U8>>(3, 174_503);
}

#[test]
fn test_por_circuit_sha256_base_8() {
    test_por_circuit::<TreeBase<Sha256Hasher<Fr>, U8>>(3, 250_987);
}

#[test]
fn test_por_circuit_poseidon_base_8() {
    test_por_circuit::<TreeBase<PoseidonHasher<Fr>, U8>>(3, 1_063);
}

#[test]
fn test_por_circuit_poseidon_sub_8_2() {
    test_por_circuit::<TreeSub<PoseidonHasher<Fr>, U8, U2>>(3, 1_377);
}

#[test]
fn test_por_circuit_poseidon_top_8_4_2() {
    test_por_circuit::<TreeTop<PoseidonHasher<Fr>, U8, U4, U2>>(3, 1_764);
}

#[test]
fn test_por_circuit_poseidon_sub_8_8() {
    // This is the shape we want for 32GiB sectors.
    test_por_circuit::<TreeSub<PoseidonHasher<Fr>, U8, U8>>(3, 1_593);
}
#[test]
fn test_por_circuit_poseidon_top_8_8_2() {
    // This is the shape we want for 64GiB secotrs.
    test_por_circuit::<TreeTop<PoseidonHasher<Fr>, U8, U8, U2>>(3, 1_907);
}

#[test]
fn test_por_circuit_poseidon_top_8_2_4() {
    // We can handle top-heavy trees with a non-zero subtree arity.
    // These should never be produced, though.
    test_por_circuit::<TreeTop<PoseidonHasher<Fr>, U8, U2, U4>>(3, 1_764);
}

fn test_por_circuit<Tree>(num_inputs: usize, num_constraints: usize)
where
    Tree: 'static + MerkleTreeTrait,
    <Tree::Hasher as Hasher>::Domain: Domain<Field = Fr>,
{
    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    // Ensure arity will evenly fill tree.
    let leaves = 64 * get_base_tree_count::<Tree>();

    // -- Basic Setup
    let (data, tree) = generate_tree::<Tree, _>(&mut rng, leaves, None);

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

        let mut cs = TestConstraintSystem::<Fr>::new();

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
    test_por_circuit_private_root::<TreeBase<PoseidonHasher<Fr>, U2>>(1_886);
}

#[test]
fn test_por_circuit_poseidon_base_4_private_root() {
    test_por_circuit_private_root::<TreeBase<PoseidonHasher<Fr>, U4>>(1_163);
}

#[test]
fn test_por_circuit_poseidon_base_8_private_root() {
    test_por_circuit_private_root::<TreeBase<PoseidonHasher<Fr>, U8>>(1_062);
}

fn test_por_circuit_private_root<Tree>(num_constraints: usize)
where
    Tree: MerkleTreeTrait,
    <Tree::Hasher as Hasher>::Domain: Domain<Field = Fr>,
{
    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64 * get_base_tree_count::<Tree>();
    for i in 0..leaves {
        // -- Basic Setup

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes(&Fr::random(&mut rng)))
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

        let mut cs = TestConstraintSystem::<Fr>::new();

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
        let packed_auth_path = multipack::compute_multipacking::<Fr>(&auth_path_bits);

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

fn create_tree<Tree>(
    labels: &[<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain],
    tmp_path: &Path,
) -> MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>
where
    Tree: MerkleTreeTrait,
    <Tree::Hasher as Hasher>::Domain: Domain<Field = Fr>,
{
    let sector_nodes = labels.len();
    let tree_name = Tree::display();
    let base_arity = Tree::Arity::to_usize();
    let sub_arity = Tree::SubTreeArity::to_usize();
    let top_arity = Tree::TopTreeArity::to_usize();

    // Create a single base-tree, a single sub-tree (out of base-trees), or a single top-tree
    // (out of sub-trees, each made of base-trees).
    if sub_arity == 0 && top_arity == 0 {
        let config = StoreConfig::new(
            tmp_path,
            tree_name.clone(),
            default_rows_to_discard(sector_nodes, base_arity),
        );
        let leafs = labels.iter().copied().map(Ok);
        MerkleTreeWrapper::try_from_iter_with_config(leafs, config)
            .unwrap_or_else(|_| panic!("failed to create non-compound-tree {}", tree_name))
    } else if top_arity == 0 {
        let base_tree_count = sub_arity;
        let leafs_per_base_tree = sector_nodes / base_tree_count;
        let rows_to_discard = default_rows_to_discard(leafs_per_base_tree, base_arity);
        let base_trees: Vec<MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity>> = (0
            ..base_tree_count)
            .map(|i| {
                let config = StoreConfig::new(
                    tmp_path,
                    format!("{}-base-{}", tree_name, i),
                    rows_to_discard,
                );
                let leafs = labels[i * leafs_per_base_tree..(i + 1) * leafs_per_base_tree]
                    .iter()
                    .copied()
                    .map(Ok);
                MerkleTreeWrapper::try_from_iter_with_config(leafs, config)
                    .unwrap_or_else(|_| panic!("failed to create {} base-tree {}", tree_name, i))
            })
            .collect();
        MerkleTreeWrapper::from_trees(base_trees)
            .unwrap_or_else(|_| panic!("failed to create {} from base-trees", tree_name))
    } else {
        let base_tree_count = top_arity * sub_arity;
        let sub_tree_count = top_arity;
        let leafs_per_base_tree = sector_nodes / base_tree_count;
        let base_trees_per_sub_tree = sub_arity;
        let rows_to_discard = default_rows_to_discard(leafs_per_base_tree, base_arity);
        let sub_trees: Vec<
            MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity, Tree::SubTreeArity>,
        > = (0..sub_tree_count)
            .map(|sub_index| {
                let first_sub_leaf = sub_index * base_trees_per_sub_tree * leafs_per_base_tree;
                let base_trees: Vec<MerkleTreeWrapper<Tree::Hasher, Tree::Store, Tree::Arity>> = (0
                    ..base_trees_per_sub_tree)
                    .map(|base_index| {
                        let config = StoreConfig::new(
                            tmp_path,
                            format!("{}-sub-{}-base-{}", tree_name, sub_index, base_index),
                            rows_to_discard,
                        );
                        let first_base_leaf = first_sub_leaf + base_index * leafs_per_base_tree;
                        let leafs = labels[first_base_leaf..first_base_leaf + leafs_per_base_tree]
                            .iter()
                            .copied()
                            .map(Ok);
                        MerkleTreeWrapper::try_from_iter_with_config(leafs, config).unwrap_or_else(
                            |_| {
                                panic!(
                                    "failed to create {} sub-tree {} base-tree {}",
                                    tree_name, sub_index, base_index,
                                )
                            },
                        )
                    })
                    .collect();
                MerkleTreeWrapper::from_trees(base_trees).unwrap_or_else(|_| {
                    panic!(
                        "failed to create {} sub-tree {} from base-trees",
                        tree_name, sub_index,
                    )
                })
            })
            .collect();
        MerkleTreeWrapper::from_sub_trees(sub_trees)
            .unwrap_or_else(|_| panic!("failed to create {} from sub-trees", tree_name))
    }
}

fn test_por_no_challenge_input<U, V, W>(sector_nodes: usize)
where
    U: PoseidonArity,
    V: PoseidonArity,
    W: PoseidonArity,
{
    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    let challenge_bit_len = sector_nodes.trailing_zeros() as usize;

    // Merkle tree storage directory.
    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path();

    // Create random TreeROld.
    let leafs: Vec<PoseidonDomain<Fr>> = (0..sector_nodes)
        .map(|_| PoseidonDomain::random(&mut rng))
        .collect();
    let tree = create_tree::<DiskTree<PoseidonHasher<Fr>, U, V, W>>(&leafs, tmp_path);
    let root = tree.root();

    let mut cs = TestConstraintSystem::<Fr>::new();

    let root = AllocatedNum::alloc(cs.namespace(|| "root"), || Ok(root.into())).unwrap();

    for c_index in 0..100 {
        let c = rng.gen::<usize>() % sector_nodes;
        let leaf = leafs[c];

        // Vanilla PoR proof
        let proof = {
            let pub_params = por::PublicParams {
                leaves: sector_nodes,
                private: false,
            };
            let pub_inputs = por::PublicInputs {
                challenge: c,
                commitment: None,
            };
            let priv_inputs =
                por::PrivateInputs::<DiskTree<PoseidonHasher<Fr>, U, V, W>> { leaf, tree: &tree };
            let proof = PoR::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");
            let is_valid = PoR::<DiskTree<PoseidonHasher<Fr>, U, V, W>>::verify(
                &pub_params,
                &pub_inputs,
                &proof,
            )
            .expect("verification failed");
            assert!(is_valid, "failed to verify por proof");
            proof.proof
        };

        let leaf = AllocatedNum::alloc(
            cs.namespace(|| format!("leaf (c_index={})", c_index)),
            || Ok(leaf.into()),
        )
        .unwrap();

        let c_bits: Vec<AllocatedBit> = (0..challenge_bit_len)
            .map(|i| {
                AllocatedBit::alloc(
                    cs.namespace(|| {
                        format!("challenge_bit (c_index={}, bit_index={})", c_index, i)
                    }),
                    Some((c >> i) & 1 == 1),
                )
                .unwrap()
            })
            .collect();

        let path_values: Vec<Vec<AllocatedNum<Fr>>> = proof
            .path()
            .into_iter()
            .enumerate()
            .map(|(height, (siblings, _insert))| {
                siblings
                    .into_iter()
                    .enumerate()
                    .map(|(i, sibling)| {
                        AllocatedNum::alloc(
                            cs.namespace(|| {
                                format!(
                                    "merkle path sibling (c_index={}, height={}, sibling_index={})",
                                    c_index, height, i,
                                )
                            }),
                            || Ok(sibling.into()),
                        )
                        .unwrap()
                    })
                    .collect()
            })
            .collect();

        por_no_challenge_input::<DiskTree<PoseidonHasher<Fr>, U, V, W>, _>(
            cs.namespace(|| format!("por (c_index={})", c_index)),
            c_bits,
            leaf,
            path_values,
            root.clone(),
        )
        .unwrap();
    }

    assert!(cs.is_satisfied());
    let pub_inputs = vec![];
    assert!(cs.verify(&pub_inputs));
}

// Test non-compound tree.
#[test]
fn test_por_no_challenge_input_2kib_8_0_0() {
    test_por_no_challenge_input::<U8, U0, U0>(1 << 6);
}

// Test compound base-sub tree with repeated arity.
#[test]
fn test_por_no_challenge_input_2kib_8_8_0() {
    test_por_no_challenge_input::<U8, U8, U0>(1 << 6);
}

// Test compound base-sub tree.
#[test]
fn test_por_no_challenge_input_8kib_8_4_0() {
    test_por_no_challenge_input::<U8, U4, U0>(1 << 8);
}

// Test compound base-sub tree.
#[test]
fn test_por_no_challenge_input_8kib_8_4_2() {
    test_por_no_challenge_input::<U8, U4, U2>(1 << 9);
}

// Test compound base-sub-top tree with repeated arity.
#[test]
fn test_por_no_challenge_input_32kib_8_8_2() {
    test_por_no_challenge_input::<U8, U8, U2>(1 << 10);
}
