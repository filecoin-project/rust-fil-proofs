use std::convert::Into;

use bellperson::bls::Fr;
use ff::Field;
use filecoin_hashers::{
    blake2s::Blake2sHasher, poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, Hasher,
};
use fr32::fr_into_bytes;
use generic_array::typenum::{U0, U2, U4};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    api_version::ApiVersion,
    drgraph::{BucketGraph, Graph, BASE_DEGREE},
    merkle::{create_base_merkle_tree, DiskStore, MerkleTreeTrait, MerkleTreeWrapper},
    por::{self, PoR},
    proof::ProofScheme,
    util::data_at_node,
    TEST_SEED,
};

type TreeBase<H, U> = MerkleTreeWrapper<H, DiskStore<<H as Hasher>::Domain>, U, U0, U0>;

#[test]
fn test_por_poseidon_base_2() {
    test_por::<TreeBase<PoseidonHasher, U2>>();
}

#[test]
fn test_por_sha256_base_2() {
    test_por::<TreeBase<Sha256Hasher, U2>>();
}

#[test]
fn test_por_blake2s_base_2() {
    test_por::<TreeBase<Blake2sHasher, U2>>();
}

#[test]
fn test_por_poseidon_base_4() {
    test_por::<TreeBase<PoseidonHasher, U4>>();
}

#[test]
fn test_por_sha256_base_4() {
    test_por::<TreeBase<Sha256Hasher, U4>>();
}

#[test]
fn test_por_blake2s_base_4() {
    test_por::<TreeBase<Blake2sHasher, U4>>();
}

fn test_por<Tree: MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 16;
    let pub_params = por::PublicParams {
        leaves,
        private: false,
    };

    let data: Vec<u8> = (0..leaves)
        .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
        .collect();
    let porep_id = [3; 32];
    let graph =
        BucketGraph::<Tree::Hasher>::new(leaves, BASE_DEGREE, 0, porep_id, ApiVersion::V1_1_0)
            .unwrap();
    let tree = create_base_merkle_tree::<Tree>(None, graph.size(), data.as_slice()).unwrap();

    let pub_inputs = por::PublicInputs {
        challenge: 3,
        commitment: Some(tree.root()),
    };

    let leaf = <Tree::Hasher as Hasher>::Domain::try_from_bytes(
        data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(),
    )
    .unwrap();

    let priv_inputs = por::PrivateInputs::new(leaf, &tree);

    let proof = PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    let is_valid =
        PoR::<Tree>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");

    assert!(is_valid);
}

#[test]
fn test_por_validates_proof_sha256_base_2() {
    test_por_validates_proof::<TreeBase<Sha256Hasher, U2>>();
}

#[test]
fn test_por_validates_proof_blake2s_base_2() {
    test_por_validates_proof::<TreeBase<Blake2sHasher, U2>>();
}

#[test]
fn test_por_validates_proof_poseidon_base_2() {
    test_por_validates_proof::<TreeBase<PoseidonHasher, U2>>();
}

#[test]
fn test_por_validates_proof_sha256_base_4() {
    test_por_validates_proof::<TreeBase<Sha256Hasher, U4>>();
}

#[test]
fn test_por_validates_proof_blake2s_base_4() {
    test_por_validates_proof::<TreeBase<Blake2sHasher, U4>>();
}

#[test]
fn test_por_validates_proof_poseidon_base_4() {
    test_por_validates_proof::<TreeBase<PoseidonHasher, U4>>();
}

fn test_por_validates_proof<Tree: MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64;
    let pub_params = por::PublicParams {
        leaves,
        private: false,
    };

    let data: Vec<u8> = (0..leaves)
        .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
        .collect();

    let porep_id = [99; 32];

    let graph =
        BucketGraph::<Tree::Hasher>::new(leaves, BASE_DEGREE, 0, porep_id, ApiVersion::V1_1_0)
            .unwrap();
    let tree = create_base_merkle_tree::<Tree>(None, graph.size(), data.as_slice()).unwrap();

    let pub_inputs = por::PublicInputs {
        challenge: 3,
        commitment: Some(tree.root()),
    };

    let leaf = <Tree::Hasher as Hasher>::Domain::try_from_bytes(
        data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(),
    )
    .unwrap();

    let priv_inputs = por::PrivateInputs::<Tree>::new(leaf, &tree);

    let good_proof =
        PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    let verified =
        PoR::<Tree>::verify(&pub_params, &pub_inputs, &good_proof).expect("verification failed");
    assert!(verified);

    // Invalidate the proof.
    let bad_proof = {
        let mut proof = good_proof;
        let mut bad_leaf = Into::<Fr>::into(proof.data);
        bad_leaf.add_assign(&Fr::one());
        proof.data = bad_leaf.into();
        proof
    };

    let verified =
        PoR::<Tree>::verify(&pub_params, &pub_inputs, &bad_proof).expect("verification failed");

    assert!(!verified);
}

#[test]
fn test_por_validates_challenge_sha256_base_2() {
    test_por_validates_challenge::<TreeBase<Sha256Hasher, U2>>();
}

#[test]
fn test_por_validates_challenge_blake2s_base_2() {
    test_por_validates_challenge::<TreeBase<Blake2sHasher, U2>>();
}

#[test]
fn test_por_validates_challenge_poseidon_base_2() {
    test_por_validates_challenge::<TreeBase<PoseidonHasher, U2>>();
}

#[test]
fn test_por_validates_challenge_sha256_base_4() {
    test_por_validates_challenge::<TreeBase<Sha256Hasher, U4>>();
}

#[test]
fn test_por_validates_challenge_blake2s_base_4() {
    test_por_validates_challenge::<TreeBase<Blake2sHasher, U4>>();
}

#[test]
fn test_por_validates_challenge_poseidon_base_4() {
    test_por_validates_challenge::<TreeBase<PoseidonHasher, U4>>();
}

fn test_por_validates_challenge<Tree: MerkleTreeTrait>() {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);

    let leaves = 64;

    let pub_params = por::PublicParams {
        leaves,
        private: false,
    };

    let data: Vec<u8> = (0..leaves)
        .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
        .collect();

    let porep_id = [32; 32];
    let graph =
        BucketGraph::<Tree::Hasher>::new(leaves, BASE_DEGREE, 0, porep_id, ApiVersion::V1_1_0)
            .unwrap();
    let tree = create_base_merkle_tree::<Tree>(None, graph.size(), data.as_slice()).unwrap();

    let pub_inputs = por::PublicInputs {
        challenge: 3,
        commitment: Some(tree.root()),
    };

    let leaf = <Tree::Hasher as Hasher>::Domain::try_from_bytes(
        data_at_node(data.as_slice(), pub_inputs.challenge).unwrap(),
    )
    .unwrap();

    let priv_inputs = por::PrivateInputs::<Tree>::new(leaf, &tree);

    let proof = PoR::<Tree>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

    // Invalidate the challenge.
    let different_pub_inputs = por::PublicInputs {
        challenge: 999,
        commitment: Some(tree.root()),
    };

    let verified = PoR::<Tree>::verify(&pub_params, &different_pub_inputs, &proof)
        .expect("verification failed");

    // A proof created with a the wrong challenge not be verified!
    assert!(!verified);
}
