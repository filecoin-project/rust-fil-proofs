use std::convert::TryInto;
use std::time::Instant;

use bellperson::groth16;
use blstrs::{Bls12, Scalar as Fr};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fil_halo2_gadgets::{
    uint32::{UInt32Chip, UInt32Config},
    ColumnBuilder,
};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Halo2Hasher};
use generic_array::typenum::{U0, U2, U8};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{self, Column, Instance},
};
use storage_proofs_core::{
    compound_proof::CompoundProof as _,
    gadgets::por::{PoRCircuit, PoRCompound},
    halo2::{
        gadgets::{
            insert::{InsertChip, InsertConfig},
            por::{empty_path, MerkleChip},
        },
        create_proof as halo2_create_proof, verify_proof as halo2_verify_proof, CircuitRows,
        Halo2Field, Halo2Keypair,
    },
    merkle::{MerkleTree, MerkleProofTrait, MerkleTreeTrait},
    por as vanilla,
};
use rand::thread_rng;

fn bench_groth16_halo2_poseidon_arity_8(c: &mut Criterion) {
    // Configure the tree height here:
    const HEIGHT: u32 = 3;
    const ARITY: usize = 8;
    const NUM_LEAFS: usize = ARITY.pow(HEIGHT);
    const CHALLENGE: usize = NUM_LEAFS / 2;

    type TreeFr = MerkleTree<PoseidonHasher<Fr>, U8>;
    type TreeFp = MerkleTree<PoseidonHasher<Fp>, U8>;

    let mut rng = thread_rng();
    let benchmark_prefix = format!("poseidon-arity-8-leafs-{}", NUM_LEAFS);

    #[derive(Clone)]
    struct MerkleConfig {
        uint32: UInt32Config<Fp>,
        poseidon: <PoseidonHasher<Fp> as Halo2Hasher<U8>>::Config,
        insert: InsertConfig<Fp, U8>,
        pi: Column<Instance>,
    }

    #[derive(Clone)]
    struct MerkleCircuit {
        leaf: Value<Fp>,
        path: Vec<Vec<Value<Fp>>>,
    }

    impl plonk::Circuit<Fp> for MerkleCircuit {
        type Config = MerkleConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MerkleCircuit {
                leaf: Value::unknown(),
                path: empty_path::<Fp, U8, U0, U0, NUM_LEAFS>(),
            }
        }

        #[allow(clippy::unwrap_used)]
        fn configure(meta: &mut plonk::ConstraintSystem<Fp>) -> Self::Config {
            let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
                .with_chip::<UInt32Chip<Fp>>()
                .with_chip::<<PoseidonHasher<Fp> as Halo2Hasher<U8>>::Chip>()
                .with_chip::<InsertChip<Fp, U8>>()
                .create_columns(meta);

            let uint32 = UInt32Chip::configure(meta, advice_eq[..9].try_into().unwrap());
            let poseidon = <PoseidonHasher<Fp> as Halo2Hasher<U8>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert = InsertChip::configure(meta, &advice_eq, &advice_neq);

            let pi = meta.instance_column();
            meta.enable_equality(pi);

            MerkleConfig {
                uint32,
                poseidon,
                insert,
                pi,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), plonk::Error> {
            // Absolute rows of public inputs.
            const CHALLENGE_ROW: usize = 0;
            const ROOT_ROW: usize = 1;

            let MerkleConfig {
                uint32: uint32_config,
                poseidon: poseidon_config,
                insert: insert_config,
                pi: pi_col,
            } = config;

            let uint32_chip = UInt32Chip::construct(uint32_config);
            let poseidon_chip = <PoseidonHasher<Fp> as Halo2Hasher<U8>>::construct(poseidon_config);
            let insert_chip = InsertChip::construct(insert_config);

            let merkle_chip = MerkleChip::<PoseidonHasher<Fp>, U8>::with_subchips(
                poseidon_chip,
                insert_chip,
                None,
                None,
            );

            let challenge_bits = uint32_chip.pi_assign_bits(
                layouter.namespace(|| "challenge"),
                pi_col,
                CHALLENGE_ROW,
            )?;

            let root = merkle_chip.compute_root(
                layouter.namespace(|| "compute merkle root"),
                &challenge_bits,
                self.leaf,
                &self.path,
            )?;
            layouter.constrain_instance(root.cell(), pi_col, ROOT_ROW)
        }
    }

    impl CircuitRows for MerkleCircuit {
        fn k(&self) -> u32 {
            let arity_bit_len = ARITY.trailing_zeros() as usize;
            let challenge_bit_len = NUM_LEAFS.trailing_zeros() as usize;
            let path_len = challenge_bit_len / arity_bit_len;

            // Decomposing a `u32` challenge into 32 bits requires 4 rows.
            let challenge_decomp_rows = 4;
            // Poseidon arity-8 hash function rows.
            let hasher_rows = <PoseidonHasher<Fp> as Halo2Hasher<U8>>::Chip::num_rows();
            // A single arity-8 insert requires 1 row.
            let insert_rows = 1;
            let num_rows = challenge_decomp_rows + path_len * (hasher_rows + insert_rows);

            // Add one to the computed `k` to ensure that there are enough rows.
            (num_rows as f32).log2().ceil() as u32 + 1
        }
    }

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
    let (halo2_circ, halo2_pub_inputs, halo2_proof, halo2_keypair) = {
        let leafs = (0..NUM_LEAFS as u64).map(|i| Fp::from(i).into());
        let leaf = Fp::from(CHALLENGE as u64);
        let tree = TreeFp::new(leafs).expect("failed to create merkle tree");
        let root: Fp = tree.root().into();
        let merkle_proof = tree.gen_proof(CHALLENGE).expect("failed to create merkle proof");

        let circ = MerkleCircuit {
            leaf: Value::known(leaf),
            path: merkle_proof
                .path()
                .iter()
                .map(|(sibs, _)| sibs.iter().copied().map(|domain| Value::known(domain.into())).collect())
                .collect(),
        };

        let pub_inputs = vec![vec![leaf, root]];

        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ)
            .expect("failed to create halo2 keypair");

        let proof = halo2_create_proof(&keypair, circ.clone(), &pub_inputs, &mut rng)
            .expect("failed to create halo2 proof");
    
        (circ, pub_inputs, proof, keypair)
    };

    let mut prover_benchmarks = c.benchmark_group(format!("{}-prover", benchmark_prefix));
    prover_benchmarks.sample_size(10);
    prover_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
        groth16::create_random_proof(groth16_circ.clone(), &groth16_params, &mut rng)
            .expect("failed to create groth16 proof")
    )));
    prover_benchmarks.bench_function("halo2", |b| b.iter(|| black_box(
        halo2_create_proof(&halo2_keypair, halo2_circ.clone(), &halo2_pub_inputs, &mut rng)
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
        halo2_verify_proof(&halo2_keypair, &halo2_proof, &halo2_pub_inputs)
            .expect("failed to verify halo2 proof")
    )));
    verifier_benchmarks.finish();
}

fn bench_groth16_halo2_sha256_arity_2(c: &mut Criterion) {
    // Configure the tree height here:
    const HEIGHT: u32 = 10;
    const ARITY: usize = 2;
    const NUM_LEAFS: usize = ARITY.pow(HEIGHT);
    const CHALLENGE: usize = NUM_LEAFS / 2;

    type TreeFr = MerkleTree<Sha256Hasher<Fr>, U2>;
    type TreeFp = MerkleTree<Sha256Hasher<Fp>, U2>;

    let mut rng = thread_rng();
    let benchmark_prefix = format!("sha256-arity-2-leafs-{}", NUM_LEAFS);

    #[derive(Clone)]
    struct MerkleConfig {
        uint32: UInt32Config<Fp>,
        sha256: <Sha256Hasher<Fp> as Halo2Hasher<U2>>::Config,
        insert: InsertConfig<Fp, U2>,
        pi: Column<Instance>,
    }

    #[derive(Clone)]
    struct MerkleCircuit {
        leaf: Value<Fp>,
        path: Vec<Vec<Value<Fp>>>,
    }

    impl plonk::Circuit<Fp> for MerkleCircuit {
        type Config = MerkleConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MerkleCircuit {
                leaf: Value::unknown(),
                path: empty_path::<Fp, U2, U0, U0, NUM_LEAFS>(),
            }
        }

        #[allow(clippy::unwrap_used)]
        fn configure(meta: &mut plonk::ConstraintSystem<Fp>) -> Self::Config {
            let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
                .with_chip::<UInt32Chip<Fp>>()
                .with_chip::<<Sha256Hasher<Fp> as Halo2Hasher<U2>>::Chip>()
                .with_chip::<InsertChip<Fp, U2>>()
                .create_columns(meta);

            let uint32 = UInt32Chip::configure(meta, advice_eq[..9].try_into().unwrap());
            let sha256 = <Sha256Hasher<Fp> as Halo2Hasher<U2>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let insert = InsertChip::configure(meta, &advice_eq, &advice_neq);

            let pi = meta.instance_column();
            meta.enable_equality(pi);

            MerkleConfig {
                uint32,
                sha256,
                insert,
                pi,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), plonk::Error> {
            // Absolute rows of public inputs.
            const CHALLENGE_ROW: usize = 0;
            const ROOT_ROW: usize = 1;

            let MerkleConfig {
                uint32: uint32_config,
                sha256: sha256_config,
                insert: insert_config,
                pi: pi_col,
            } = config;

            <Sha256Hasher<Fp> as Halo2Hasher<U2>>::load(&mut layouter, &sha256_config)?;

            let uint32_chip = UInt32Chip::construct(uint32_config);
            let sha256_chip = <Sha256Hasher<Fp> as Halo2Hasher<U2>>::construct(sha256_config);
            let insert_chip = InsertChip::construct(insert_config);

            let merkle_chip = MerkleChip::<Sha256Hasher<Fp>, U2>::with_subchips(
                sha256_chip,
                insert_chip,
                None,
                None,
            );

            let challenge_bits = uint32_chip.pi_assign_bits(
                layouter.namespace(|| "challenge"),
                pi_col,
                CHALLENGE_ROW,
            )?;

            let root = merkle_chip.compute_root(
                layouter.namespace(|| "compute merkle root"),
                &challenge_bits,
                self.leaf,
                &self.path,
            )?;
            layouter.constrain_instance(root.cell(), pi_col, ROOT_ROW)
        }
    }

    impl CircuitRows for MerkleCircuit {
        fn k(&self) -> u32 {
            17
        }
    }

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
    let (halo2_circ, halo2_pub_inputs, halo2_proof, halo2_keypair) = {
        let leafs = (0..NUM_LEAFS as u64).map(|i| Fp::from(i).into());
        let leaf = Fp::from(CHALLENGE as u64);
        let tree = TreeFp::new(leafs).expect("failed to create merkle tree");
        let root: Fp = tree.root().into();
        let merkle_proof = tree.gen_proof(CHALLENGE).expect("failed to create merkle proof");

        let circ = MerkleCircuit {
            leaf: Value::known(leaf),
            path: merkle_proof
                .path()
                .iter()
                .map(|(sibs, _)| sibs.iter().copied().map(|domain| Value::known(domain.into())).collect())
                .collect(),
        };

        let pub_inputs = vec![vec![leaf, root]];

        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ)
            .expect("failed to create halo2 keypair");

        let proof = halo2_create_proof(&keypair, circ.clone(), &pub_inputs, &mut rng)
            .expect("failed to create halo2 proof");
    
        (circ, pub_inputs, proof, keypair)
    };

    let mut prover_benchmarks = c.benchmark_group(format!("{}-prover", benchmark_prefix));
    prover_benchmarks.sample_size(10);
    prover_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
        groth16::create_random_proof(groth16_circ.clone(), &groth16_params, &mut rng)
            .expect("failed to create groth16 proof")
    )));
    // Only benchmark halo2 once because it takes a long time to run.
    {
        let start = Instant::now();
        black_box(
            halo2_create_proof(&halo2_keypair, halo2_circ.clone(), &halo2_pub_inputs, &mut rng)
                .expect("failed to create halo2 proof")
        );
        println!("\n{}-prover/halo2", benchmark_prefix);
        println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
    }
    prover_benchmarks.finish();

    let mut verifier_benchmarks = c.benchmark_group(format!("{}-verifier", benchmark_prefix));
    verifier_benchmarks.sample_size(10);
    verifier_benchmarks.bench_function("groth16", |b| b.iter(|| black_box(
        groth16::verify_proof(&groth16_vk, &groth16_proof, &groth16_pub_inputs)
            .expect("failed to verify groth16 proof")
    )));
    // Only benchmark halo2 once because it takes a long time to run.
    {
        let start = Instant::now();
        black_box(
            halo2_verify_proof(&halo2_keypair, &halo2_proof, &halo2_pub_inputs)
                .expect("failed to verify halo2 proof")
        );
        println!("\n{}-verifier/halo2", benchmark_prefix);
        println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
    }
    verifier_benchmarks.finish();
}

criterion_group!(benches, bench_groth16_halo2_poseidon_arity_8, bench_groth16_halo2_sha256_arity_2);
criterion_main!(benches);
