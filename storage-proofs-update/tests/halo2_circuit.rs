#![cfg(feature = "isolated-testing")]

use ff::PrimeFieldBits;
use filecoin_hashers::{Domain, HashFunction, Hasher, PoseidonArity};
use generic_array::typenum::{U0, U2, U4, U8};
use halo2_proofs::{arithmetic::FieldExt, dev::MockProver, pasta::Fp};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use storage_proofs_core::{
    merkle::{MerkleProof, MerkleTreeTrait},
    TEST_SEED,
};
use storage_proofs_update::{
    constants::{
        hs, validate_tree_r_shape, TreeDArity, TreeDDomain, TreeDHasher, TreeR, TreeRDomain,
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

fn test_empty_sector_update_circuit<F, U, V, W, const SECTOR_NODES: usize>()
where
    F: FieldExt + PrimeFieldBits,
    U: PoseidonArity<F>,
    V: PoseidonArity<F>,
    W: PoseidonArity<F>,
    TreeDArity: PoseidonArity<F>,
    TreeDHasher<F>: Hasher<Domain = TreeDDomain<F>>,
    TreeDDomain<F>: Domain<Field = F>,
    TreeRHasher<F>: Hasher<Domain = TreeRDomain<F>>,
    TreeRDomain<F>: Domain<Field = F>,
    TreeR<F, U, V, W>:
        MerkleTreeTrait<Hasher = TreeRHasher<F>, Proof = MerkleProof<TreeRHasher<F>, U, V, W>>,
{
    validate_tree_r_shape::<U, V, W>(SECTOR_NODES);

    let hs = hs(SECTOR_NODES);
    let h = hs[H_SELECT.trailing_zeros() as usize];

    let mut rng = XorShiftRng::from_seed(TEST_SEED);

    // Merkle tree storage directory.
    let tmp_dir = tempdir().unwrap();
    let tmp_path = tmp_dir.path();

    // Create random TreeROld.
    let labels_r_old: Vec<TreeRDomain<F>> = (0..SECTOR_NODES)
        .map(|_| TreeRDomain::random(&mut rng))
        .collect();
    let tree_r_old: TreeR<F, U, V, W> = create_tree_r_old(&labels_r_old, tmp_path);
    let root_r_old = tree_r_old.root();
    let comm_c = TreeRDomain::<F>::random(&mut rng);
    let comm_r_old = <TreeRHasher<F> as Hasher>::Function::hash2(&comm_c, &root_r_old);

    // Create random TreeDNew.
    let labels_d_new: Vec<TreeDDomain<F>> = (0..SECTOR_NODES)
        .map(|_| TreeDDomain::random(&mut rng))
        .collect();
    let tree_d_new = create_tree_d_new(&labels_d_new, tmp_path);
    let comm_d_new = tree_d_new.root();

    // `phi = H(comm_d_new || comm_r_old)`
    let phi = phi(&comm_d_new, &comm_r_old);

    // Encode `labels_d_new` into `labels_r_new` and create TreeRNew.
    let labels_r_new = encode_new_replica(&labels_r_old, &labels_d_new, &phi, h);
    let tree_r_new: TreeR<F, U, V, W> = create_tree_r_new(&labels_r_new, tmp_path);
    let root_r_new = tree_r_new.root();
    let comm_r_new = <TreeRHasher<F> as Hasher>::Function::hash2(&comm_c, &root_r_new);

    let pub_params = PublicParams::from_sector_size((SECTOR_NODES << 5) as u64);

    let get_high_bits_shr = pub_params.challenge_bit_len - h;
    let rhos = vanilla::rhos(h, &phi);

    for k in 0..pub_params.partition_count {
        // Generate vanilla-proof.
        let apex_leafs = get_apex_leafs(&tree_d_new, k);

        let challenges: Vec<u32> = Challenges::new(SECTOR_NODES, comm_r_new, k)
            .take(pub_params.challenge_count)
            .collect();

        let rhos: Vec<F> = challenges
            .iter()
            .map(|c| {
                let high = (c >> get_high_bits_shr) as usize;
                rhos[high]
            })
            .collect();

        let challenge_proofs: Vec<vanilla::ChallengeProof<F, U, V, W>> = challenges
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
        let pub_inputs = circuit::PublicInputs::<F, SECTOR_NODES>::new(
            k,
            comm_r_old.into(),
            comm_d_new.into(),
            comm_r_new.into(),
            challenges,
            rhos,
        );

        let pub_inputs_vec = pub_inputs.to_vec();

        let priv_inputs = circuit::PrivateInputs::<F, U, V, W, SECTOR_NODES>::new(
            comm_c.into(),
            &apex_leafs
                .iter()
                .copied()
                .map(Into::into)
                .collect::<Vec<F>>(),
            &challenge_proofs,
        );

        let circ = EmptySectorUpdateCircuit {
            pub_inputs,
            priv_inputs,
        };

        let k = EmptySectorUpdateCircuit::<F, U, V, W, SECTOR_NODES>::k();
        let prover = MockProver::run(k, &circ, pub_inputs_vec).unwrap();
        assert!(prover.verify().is_ok());
    }
}

#[test]
fn test_empty_sector_update_circuit_1kib_halo2() {
    test_empty_sector_update_circuit::<Fp, U8, U4, U0, SECTOR_SIZE_1_KIB>();
}

#[test]
fn test_empty_sector_update_circuit_2kib_halo2() {
    test_empty_sector_update_circuit::<Fp, U8, U0, U0, SECTOR_SIZE_2_KIB>();
}

#[test]
fn test_empty_sector_update_circuit_4kib_halo2() {
    test_empty_sector_update_circuit::<Fp, U8, U2, U0, SECTOR_SIZE_4_KIB>();
}

#[test]
fn test_empty_sector_update_circuit_8kib_halo2() {
    test_empty_sector_update_circuit::<Fp, U8, U4, U0, SECTOR_SIZE_8_KIB>();
}

#[test]
fn test_empty_sector_update_circuit_16kib_halo2() {
    test_empty_sector_update_circuit::<Fp, U8, U8, U0, SECTOR_SIZE_16_KIB>();
}

#[test]
fn test_empty_sector_update_circuit_32kib_halo2() {
    test_empty_sector_update_circuit::<Fp, U8, U8, U2, SECTOR_SIZE_32_KIB>();
}
