#![allow(unused_imports)]
#![allow(dead_code)]

use bellperson::{util_cs::bench_cs::BenchCS, util_cs::test_cs::TestConstraintSystem, Circuit};
use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{U0, U4, U8};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{merkle::MerkleTreeTrait, TEST_SEED};
use storage_proofs_update::{
    constants::{
        self, hs, validate_tree_r_shape, SECTOR_SIZE_1_KIB, SECTOR_SIZE_32_GIB, SECTOR_SIZE_8_KIB,
    },
    phi,
    poseidon::{circuit, vanilla, EmptySectorUpdateCircuit},
    Challenges, PublicParams,
};
use tempfile::tempdir;

mod common;

use common::{
    create_tree_d_new_poseidon, create_tree_r_new, create_tree_r_old, encode_new_replica, H_SELECT,
};

type TreeR<U, V, W> = constants::TreeR<Fr, U, V, W>;
type TreeRDomain = constants::TreeRDomain<Fr>;
type TreeRHasher = constants::TreeRHasher<Fr>;

fn test_empty_sector_update_circuit<U, V, W>(sector_nodes: usize, constraints_expected: usize)
where
    U: PoseidonArity<Fr>,
    V: PoseidonArity<Fr>,
    W: PoseidonArity<Fr>,
{
    validate_tree_r_shape::<U, V, W>(sector_nodes);

    let sector_bytes = sector_nodes << 5;
    let hs = hs(sector_nodes);
    let h = hs[H_SELECT.trailing_zeros() as usize];

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    // Merkle tree storage directory.
    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path();

    // Create random TreeROld.
    let labels_r_old: Vec<TreeRDomain> = (0..sector_nodes)
        .map(|_| TreeRDomain::random(&mut rng))
        .collect();
    let tree_r_old: TreeR<U, V, W> = create_tree_r_old(&labels_r_old, tmp_path);
    let root_r_old = tree_r_old.root();
    let comm_c = TreeRDomain::random(&mut rng);
    let comm_r_old = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &root_r_old);

    // Create random TreeDNew.
    let labels_d_new: Vec<TreeRDomain> = (0..sector_nodes)
        .map(|_| TreeRDomain::random(&mut rng))
        .collect();
    let tree_d_new: TreeR<U, V, W> = create_tree_d_new_poseidon(&labels_d_new, tmp_path);
    let comm_d_new = tree_d_new.root();

    // `phi = H(comm_d_new || comm_r_old)`
    let phi = phi(&comm_d_new, &comm_r_old);

    // Encode `labels_d_new` into `labels_r_new` and create TreeRNew.
    let labels_r_new = encode_new_replica(&labels_r_old, &labels_d_new, &phi, h);
    let tree_r_new: TreeR<U, V, W> = create_tree_r_new(&labels_r_new, tmp_path);
    let root_r_new = tree_r_new.root();
    let comm_r_new = <TreeRHasher as Hasher>::Function::hash2(&comm_c, &root_r_new);

    let pub_params = PublicParams::from_sector_size_poseidon(sector_bytes as u64);

    {
        // Generate vanilla-proof.
        let challenge_proofs: Vec<vanilla::ChallengeProof<Fr, U, V, W>> =
            Challenges::new_poseidon(sector_nodes, comm_r_new)
                .enumerate()
                .take(pub_params.challenge_count)
                .map(|(i, c)| {
                    let c = c as usize;
                    let proof_r_old = tree_r_old.gen_proof(c).unwrap_or_else(|_| {
                        panic!("failed to generate `proof_r_old` for c_{}={}", i, c)
                    });
                    let proof_d_new = tree_d_new.gen_proof(c).unwrap_or_else(|_| {
                        panic!("failed to generate `proof_d_new` for c_{}={}", i, c)
                    });
                    let proof_r_new = tree_r_new.gen_proof(c).unwrap_or_else(|_| {
                        panic!("failed to generate `proof_r_new` for c_{}={}", i, c)
                    });

                    vanilla::ChallengeProof {
                        proof_r_old,
                        proof_d_new,
                        proof_r_new,
                    }
                })
                .collect();
        assert_eq!(challenge_proofs.len(), pub_params.challenge_count);

        // Create circuit.
        let pub_inputs =
            circuit::PublicInputs::new(sector_nodes, h, comm_r_old, comm_d_new, comm_r_new);

        let pub_inputs_vec = pub_inputs.to_vec();

        let priv_inputs = circuit::PrivateInputs::new(comm_c, &challenge_proofs);

        let circuit = EmptySectorUpdateCircuit::<U, V, W> {
            pub_params,
            pub_inputs,
            priv_inputs,
        };

        let mut cs = TestConstraintSystem::<Fr>::new();
        circuit.synthesize(&mut cs).expect("failed to synthesize");
        assert!(cs.is_satisfied());
        assert!(cs.verify(&pub_inputs_vec));
        assert_eq!(cs.num_constraints(), constraints_expected);
    }
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_poseidon_circuit_1kib() {
    test_empty_sector_update_circuit::<U8, U4, U0>(SECTOR_SIZE_1_KIB, 32164); //old 1248389
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_poseidon_circuit_8kib() {
    test_empty_sector_update_circuit::<U8, U4, U0>(SECTOR_SIZE_8_KIB, 47974); //old 2620359
}

#[test]
#[ignore]
fn test_empty_sector_update_poseidon_constraints_32gib() {
    let pub_inputs = circuit::PublicInputs::empty();

    let priv_inputs = circuit::PrivateInputs::empty(SECTOR_SIZE_32_GIB);

    let circuit = EmptySectorUpdateCircuit::<U8, U8, U0> {
        pub_params: PublicParams::from_sector_size_poseidon(SECTOR_SIZE_32_GIB as u64 * 32),
        pub_inputs,
        priv_inputs,
    };

    let mut cs = BenchCS::new();
    circuit.synthesize(&mut cs).expect("failed to synthesize");
    assert_eq!(cs.num_constraints(), 22305906)
}
