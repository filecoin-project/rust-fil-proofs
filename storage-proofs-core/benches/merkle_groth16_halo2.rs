use std::time::Instant;

use bellperson::groth16;
use blstrs::{Bls12, Scalar as Fr};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher};
use generic_array::typenum::{Unsigned, U0};
use halo2_proofs::pasta::Fp;
use storage_proofs_core::{
    compound_proof::CompoundProof as _,
    gadgets::por::{PoRCircuit, PoRCompound},
    halo2::{self, gadgets::por::test_circuit::MerkleCircuit, CircuitRows, Halo2Field, Halo2Keypair},
    merkle::{MerkleTree, MerkleProofTrait, MerkleTreeTrait},
    por as vanilla,
};
use rand::thread_rng;

fn bench_groth16_halo2_poseidon(c: &mut Criterion) {
    // Configure the tree height, arity, and whether or not to benchmark batch proving here:
    const HEIGHT: u32 = 10;
    type A = generic_array::typenum::U4;
    const ARITY: usize = 4;
    const BATCH_SIZE: Option<usize> = Some(10);

    assert_eq!(A::to_usize(), ARITY);

    const NUM_LEAFS: usize = ARITY.pow(HEIGHT);
    const CHALLENGE: usize = NUM_LEAFS / 2;

    type TreeFr = MerkleTree<PoseidonHasher<Fr>, A>;
    type TreeFp = MerkleTree<PoseidonHasher<Fp>, A>;

    let mut rng = thread_rng();

    // Groth16 prover and verifier setup.
    let (groth16_circ, groth16_pub_inputs, groth16_proof, groth16_params, groth16_vk) = {
        let vanilla_pub_params = vanilla::PublicParams {
            leaves: NUM_LEAFS,
            // Check the calculated Merkle root against public input.
            private: false,
        };

        let blank_circuit = PoRCompound::<TreeFr>::blank_circuit(&vanilla_pub_params);
        let params = groth16::generate_random_parameters::<Bls12, _, _>(blank_circuit, &mut rng)
            .expect("failed to create groth16 params");
        let vk = groth16::prepare_verifying_key(&params.vk);

        let leafs = (0..NUM_LEAFS as u64).map(|i| Fr::from(i).into());
        let tree = TreeFr::new(leafs).expect("failed to create merkle tree");
        let merkle_proof = tree.gen_proof(CHALLENGE).expect("failed to create merkle proof");

        let vanilla_pub_inputs = vanilla::PublicInputs {
            commitment: Some(tree.root()),
            challenge: CHALLENGE,
        };
        let pub_inputs = PoRCompound::<TreeFr>::generate_public_inputs(
            &vanilla_pub_inputs,
            &vanilla_pub_params,
            None,
        )
        .expect("failed to create groth16 public inputs");

        let circ = PoRCircuit::<TreeFr>::new(merkle_proof.clone(), false);

        let proof = groth16::create_random_proof(circ.clone(), &params, &mut rng)
            .expect("failed to create groth16 proof");

        (circ, pub_inputs, proof, params, vk)
    };

    // Halo2 prover and verifier setup.
    let (halo2_circ, halo2_pub_inputs, halo2_proof, halo2_keypair, k) = {
        let leafs = (0..NUM_LEAFS as u64).map(|i| Fp::from(i).into());
        let leaf = Fp::from(CHALLENGE as u64);
        let tree = TreeFp::new(leafs).expect("failed to create merkle tree");
        let root: Fp = tree.root().into();
        let merkle_proof = tree.gen_proof(CHALLENGE).expect("failed to create merkle proof");
        let path: Vec<Vec<Fp>> = merkle_proof
            .path()
            .iter()
            .map(|(sibs, _)| sibs.iter().copied().map(Into::into).collect())
            .collect();

        let circ = MerkleCircuit::<PoseidonHasher<Fp>, A, U0, U0, NUM_LEAFS>::new(leaf, path);
        let pub_inputs = vec![vec![leaf, root]];

        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ)
            .expect("failed to create halo2 keypair");

        let proof = halo2::create_proof(&keypair, circ.clone(), &pub_inputs, &mut rng)
            .expect("failed to create halo2 proof");

        let k = circ.k();

        (circ, pub_inputs, proof, keypair, k)
    };

    let benchmark_prefix = format!("merkle-poseidon-arity={}-height={}-k={}", ARITY, HEIGHT, k);

    if BATCH_SIZE.is_none() {
        let mut prover_benchmarks = c.benchmark_group(format!("{}-prover", benchmark_prefix));
        prover_benchmarks.sample_size(10);
        prover_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
            groth16::create_random_proof(groth16_circ.clone(), &groth16_params, &mut rng)
                .expect("failed to create groth16 proof")
        )));
        prover_benchmarks.bench_function("halo2", |b| b.iter(|| black_box(
            halo2::create_proof(&halo2_keypair, halo2_circ.clone(), &halo2_pub_inputs, &mut rng)
                .expect("failed to create halo2 proof")
        )));
        prover_benchmarks.finish();

        let mut verifier_benchmarks = c.benchmark_group(format!("{}-verifier", benchmark_prefix));
        verifier_benchmarks.sample_size(10);
        verifier_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
            groth16::verify_proof(&groth16_vk, &groth16_proof, &groth16_pub_inputs)
                .expect("failed to verify groth16 proof")
        )));
        verifier_benchmarks.bench_function("halo2", |b| b.iter(|| black_box(
            halo2::verify_proof(&halo2_keypair, &halo2_proof, &halo2_pub_inputs)
                .expect("failed to verify halo2 proof")
        )));
        verifier_benchmarks.finish();
    } else {
        let batch_size = BATCH_SIZE.unwrap();
        let benchmark_prefix = format!("{}-batch={}", benchmark_prefix, batch_size);

        let groth16_batch_circs = vec![groth16_circ; batch_size];
        let groth16_batch_pub_inputs = vec![groth16_pub_inputs; batch_size];
        let groth16_batch_proofs = groth16::create_random_proof_batch(
            groth16_batch_circs.clone(),
            &groth16_params,
            &mut rng,
        )
        .expect("failed to create groth16 batch proof");
        let groth16_batch_proofs: Vec<&groth16::Proof<Bls12>> =
            groth16_batch_proofs.iter().collect();

        let halo2_batch_circs = vec![halo2_circ; batch_size];
        let halo2_batch_pub_inputs = vec![halo2_pub_inputs; batch_size];
        let halo2_batch_proof = halo2::create_batch_proof(
            &halo2_keypair,
            &halo2_batch_circs,
            &halo2_batch_pub_inputs,
            &mut rng,
        )
        .expect("failed to create halo2 batch proof");

        let mut prover_benchmarks = c.benchmark_group(format!("{}-prover", benchmark_prefix));
        prover_benchmarks.sample_size(10);
        prover_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
            groth16::create_random_proof_batch(groth16_batch_circs.clone(), &groth16_params, &mut rng)
                .expect("failed to create groth16 batch proof")
        )));
        prover_benchmarks.bench_function("halo2", |b| b.iter(|| black_box(
            halo2::create_batch_proof(&halo2_keypair, &halo2_batch_circs, &halo2_batch_pub_inputs, &mut rng)
                .expect("failed to create halo2 batch proof")
        )));
        prover_benchmarks.finish();

        let mut verifier_benchmarks = c.benchmark_group(format!("{}-verifier", benchmark_prefix));
        verifier_benchmarks.sample_size(10);
        verifier_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
            groth16::verify_proofs_batch(&groth16_vk, &mut rng, &groth16_batch_proofs, &groth16_batch_pub_inputs)
                .expect("failed to verify groth16 batch proof")
        )));
        verifier_benchmarks.bench_function("halo2", |b| b.iter(|| black_box(
            halo2::verify_proofs(&halo2_keypair, &halo2_batch_proof, &halo2_batch_pub_inputs)
                .expect("failed to verify halo2 batch proof")
        )));
        verifier_benchmarks.finish();
    }
}

fn bench_groth16_halo2_sha256_arity_2(c: &mut Criterion) {
    // Configure the tree height and arity here:
    const HEIGHT: u32 = 10;
    type A = generic_array::typenum::U2;
    const ARITY: usize = 2;

    assert_eq!(A::to_usize(), ARITY);

    const NUM_LEAFS: usize = ARITY.pow(HEIGHT);
    const CHALLENGE: usize = NUM_LEAFS / 2;

    type TreeFr = MerkleTree<Sha256Hasher<Fr>, A>;
    type TreeFp = MerkleTree<Sha256Hasher<Fp>, A>;

    let mut rng = thread_rng();

    // Groth16 prover and verifier setup.
    let (groth16_circ, groth16_pub_inputs, groth16_proof, groth16_params, groth16_vk) = {
        let vanilla_pub_params = vanilla::PublicParams {
            leaves: NUM_LEAFS,
            // Check the calculated Merkle root against public input.
            private: false,
        };

        let blank_circuit = PoRCompound::<TreeFr>::blank_circuit(&vanilla_pub_params);
        let params = groth16::generate_random_parameters::<Bls12, _, _>(blank_circuit, &mut rng)
            .expect("failed to create groth16 params");
        let vk = groth16::prepare_verifying_key(&params.vk);

        let leafs = (0..NUM_LEAFS as u64).map(|i| Fr::from(i).into());
        let tree = TreeFr::new(leafs).expect("failed to create merkle tree");
        let merkle_proof = tree.gen_proof(CHALLENGE).expect("failed to create merkle proof");

        let vanilla_pub_inputs = vanilla::PublicInputs {
            commitment: Some(tree.root()),
            challenge: CHALLENGE,
        };
        let pub_inputs = PoRCompound::<TreeFr>::generate_public_inputs(
            &vanilla_pub_inputs,
            &vanilla_pub_params,
            None,
        )
        .expect("failed to create groth16 public inputs");

        let circ = PoRCircuit::<TreeFr>::new(merkle_proof.clone(), false);

        let proof = groth16::create_random_proof(circ.clone(), &params, &mut rng)
            .expect("failed to create groth16 proof");

        (circ, pub_inputs, proof, params, vk)
    };

    // Halo2 prover and verifier setup.
    let (halo2_circ, halo2_pub_inputs, halo2_proof, halo2_keypair, k) = {
        let leafs = (0..NUM_LEAFS as u64).map(|i| Fp::from(i).into());
        let leaf = Fp::from(CHALLENGE as u64);
        let tree = TreeFp::new(leafs).expect("failed to create merkle tree");
        let root: Fp = tree.root().into();
        let merkle_proof = tree.gen_proof(CHALLENGE).expect("failed to create merkle proof");
        let path: Vec<Vec<Fp>> = merkle_proof
            .path()
            .iter()
            .map(|(sibs, _)| sibs.iter().copied().map(Into::into).collect())
            .collect();

        let circ = MerkleCircuit::<Sha256Hasher<Fp>, A, U0, U0, NUM_LEAFS>::new(leaf, path);
        let pub_inputs = vec![vec![leaf, root]];

        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ)
            .expect("failed to create halo2 keypair");

        let proof = halo2::create_proof(&keypair, circ.clone(), &pub_inputs, &mut rng)
            .expect("failed to create halo2 proof");

        let k = circ.k();
    
        (circ, pub_inputs, proof, keypair, k)
    };

    let benchmark_prefix = format!("merkle-sha256-arity={}-height={}-k={}", ARITY, HEIGHT, k);

    let mut prover_benchmarks = c.benchmark_group(format!("{}-prover", benchmark_prefix));
    prover_benchmarks.sample_size(10);
    prover_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
        groth16::create_random_proof(groth16_circ.clone(), &groth16_params, &mut rng)
            .expect("failed to create groth16 proof")
    )));
    prover_benchmarks.finish();
    // Only benchmark halo2 once because it takes a long time to run.
    {
        let start = Instant::now();
        black_box(
            halo2::create_proof(&halo2_keypair, halo2_circ.clone(), &halo2_pub_inputs, &mut rng)
                .expect("failed to create halo2 proof")
        );
        println!("\n{}-prover/halo2", benchmark_prefix);
        println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
    }

    let mut verifier_benchmarks = c.benchmark_group(format!("{}-verifier", benchmark_prefix));
    verifier_benchmarks.sample_size(10);
    verifier_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
        groth16::verify_proof(&groth16_vk, &groth16_proof, &groth16_pub_inputs)
            .expect("failed to verify groth16 proof")
    )));
    verifier_benchmarks.finish();
    // Only benchmark halo2 once because it takes a long time to run.
    {
        let start = Instant::now();
        black_box(
            halo2::verify_proof(&halo2_keypair, &halo2_proof, &halo2_pub_inputs)
                .expect("failed to verify halo2 proof")
        );
        println!("\n{}-verifier/halo2", benchmark_prefix);
        println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
    }
}

criterion_group!(benches, bench_groth16_halo2_poseidon/*, bench_groth16_halo2_sha256_arity_2*/);
criterion_main!(benches);
