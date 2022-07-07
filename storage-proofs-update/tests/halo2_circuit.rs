#![allow(dead_code, unused_imports)]

use filecoin_hashers::{Domain, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{U0, U2, U4, U8};
use halo2_proofs::{dev::MockProver, pasta::Fp};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    halo2::{create_proof, verify_proof, CircuitRows, Halo2Field, Halo2Keypair},
    merkle::MerkleTreeTrait,
    TEST_SEED,
};
use storage_proofs_update::{
    constants::{
        hs, validate_tree_r_shape, TreeDDomain, TreeR, TreeRDomain,
        TreeRHasher, SECTOR_SIZE_16_KIB, SECTOR_SIZE_1_KIB, SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_KIB,
        SECTOR_SIZE_4_KIB, SECTOR_SIZE_8_KIB,
    },
    halo2::circuit::{self, EmptySectorUpdateCircuit},
    phi, vanilla, Challenges, PublicParams,
};
use tempfile::tempdir;

mod common;

use common::{
    create_tree_d_new, create_tree_r_new, create_tree_r_old, encode_new_replica, get_apex_leafs,
    H_SELECT,
};

fn test_empty_sector_update_circuit<U, V, W, const SECTOR_NODES: usize>(gen_halo2_proof: bool)
where
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    validate_tree_r_shape::<U, V, W>(SECTOR_NODES);

    let hs = hs(SECTOR_NODES);
    let h = hs[H_SELECT.trailing_zeros() as usize];

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    // Merkle tree storage directory.
    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path();

    // Create random TreeROld.
    let labels_r_old: Vec<TreeRDomain<Fp>> = (0..SECTOR_NODES)
        .map(|_| TreeRDomain::<Fp>::random(&mut rng))
        .collect();
    let tree_r_old: TreeR<Fp, U, V, W> = create_tree_r_old(&labels_r_old, tmp_path);
    let root_r_old = tree_r_old.root();
    let comm_c = TreeRDomain::<Fp>::random(&mut rng);
    let comm_r_old = <TreeRHasher<Fp> as Hasher>::Function::hash2(&comm_c, &root_r_old);

    // Create random TreeDNew.
    let labels_d_new: Vec<TreeDDomain<Fp>> = (0..SECTOR_NODES)
        .map(|_| TreeDDomain::<Fp>::random(&mut rng))
        .collect();
    let tree_d_new = create_tree_d_new(&labels_d_new, tmp_path);
    let comm_d_new = tree_d_new.root();

    // `phi = H(comm_d_new || comm_r_old)`
    let phi = phi(&comm_d_new, &comm_r_old);

    // Encode `labels_d_new` into `labels_r_new` and create TreeRNew.
    let labels_r_new = encode_new_replica(&labels_r_old, &labels_d_new, &phi, h);
    let tree_r_new: TreeR<Fp, U, V, W> = create_tree_r_new(&labels_r_new, tmp_path);
    let root_r_new = tree_r_new.root();
    let comm_r_new = <TreeRHasher<Fp> as Hasher>::Function::hash2(&comm_c, &root_r_new);

    let pub_params = PublicParams::from_sector_size((SECTOR_NODES << 5) as u64);

    let get_high_bits_shr = pub_params.challenge_bit_len - h;
    let rhos = vanilla::rhos(h, &phi);

    for k in 0..pub_params.partition_count {
        // Generate vanilla-proof.
        let apex_leafs = get_apex_leafs(&tree_d_new, k);

        let challenges: Vec<u32> = Challenges::<Fp>::new(SECTOR_NODES, comm_r_new, k)
            .take(pub_params.challenge_count)
            .collect();

        let rhos: Vec<Fp> = challenges
            .iter()
            .map(|c| {
                let high = (c >> get_high_bits_shr) as usize;
                rhos[high]
            })
            .collect();

        let challenge_proofs: Vec<vanilla::ChallengeProof<Fp, U, V, W>> = challenges
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let c = *c as usize;
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

        // Create circuit.
        let pub_inputs = circuit::PublicInputs::<Fp, SECTOR_NODES>::new(
            k,
            comm_r_old.into(),
            comm_d_new.into(),
            comm_r_new.into(),
            challenges,
            rhos,
        );

        let pub_inputs_vec = pub_inputs.to_vec();

        let priv_inputs = circuit::PrivateInputs::<Fp, U, V, W, SECTOR_NODES>::new(
            comm_c.into(),
            &apex_leafs
                .iter()
                .copied()
                .map(Into::into)
                .collect::<Vec<Fp>>(),
            &challenge_proofs,
        );

        let circ = EmptySectorUpdateCircuit {
            pub_inputs,
            priv_inputs,
        };

        let prover = MockProver::run(circ.k(), &circ, pub_inputs_vec.clone())
            .expect("halo2 MockProver failed");
        assert!(prover.verify().is_ok());

        if gen_halo2_proof {
            let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ).unwrap();
            let proof = create_proof(&keypair, circ, &pub_inputs_vec, &mut rng)
                .expect("failed to generate halo2 proof");
            verify_proof(&keypair, &proof, &pub_inputs_vec).expect("failed to verify halo2 proof");
        }
    }
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_circuit_1kib_halo2() {
    // Halo2 keygen, proving, and verifying are slow and consume a lot of memory, thus we only test
    // those for a small sector size circuit (the halo2 compound proof tests will run the halo2
    // prover and verifier for larger sector sizes).
    test_empty_sector_update_circuit::<U8, U4, U0, SECTOR_SIZE_1_KIB>(true);
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_circuit_2kib_halo2() {
    test_empty_sector_update_circuit::<U8, U0, U0, SECTOR_SIZE_2_KIB>(false);
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_circuit_4kib_halo2() {
    test_empty_sector_update_circuit::<U8, U2, U0, SECTOR_SIZE_4_KIB>(false);
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_circuit_8kib_halo2() {
    test_empty_sector_update_circuit::<U8, U4, U0, SECTOR_SIZE_8_KIB>(false);
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_circuit_16kib_halo2() {
    test_empty_sector_update_circuit::<U8, U8, U0, SECTOR_SIZE_16_KIB>(false);
}

#[test]
#[cfg(feature = "isolated-testing")]
fn test_empty_sector_update_circuit_32kib_halo2() {
    test_empty_sector_update_circuit::<U8, U8, U2, SECTOR_SIZE_32_KIB>(false);
}
