use std::any::TypeId;
use std::convert::TryInto;
use std::marker::PhantomData;
use std::time::Instant;

use bellperson::groth16;
use blstrs::{Bls12, Scalar as Fr};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fil_halo2_gadgets::{
    uint32::{UInt32Chip, UInt32Config},
    ColumnBuilder,
};
use filecoin_hashers::{
    poseidon::PoseidonHasher, sha256::Sha256Hasher, Halo2Hasher, Hasher, PoseidonArity,
};
use generic_array::typenum::{Unsigned, U0};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{self, Circuit, Column, ConstraintSystem, Instance},
};
use rand::thread_rng;
use storage_proofs_core::{
    compound_proof::CompoundProof as _,
    gadgets::por::{PoRCircuit, PoRCompound},
    halo2::{
        self,
        gadgets::{
            insert::{InsertChip, InsertConfig},
            por::{transmute_arity, MerkleChip},
        },
        CircuitRows, Halo2Field, Halo2Keypair,
    },
    merkle::{MerkleProofTrait, MerkleTree, MerkleTreeTrait},
    por as vanilla,
};

#[derive(Clone)]
pub struct MerkleCircuitConfig<H, U, V, W, const LEAFS: usize>
where
    H: 'static + Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    pub uint32: UInt32Config<Fp>,
    pub base_hasher: <H as Halo2Hasher<U>>::Config,
    pub base_insert: InsertConfig<Fp, U>,
    pub sub: Option<(<H as Halo2Hasher<V>>::Config, InsertConfig<Fp, V>)>,
    pub top: Option<(<H as Halo2Hasher<W>>::Config, InsertConfig<Fp, W>)>,
    pub pi: Column<Instance>,
}

#[derive(Clone)]
pub struct MerkleCircuit<H, U, V, W, const LEAFS: usize>
where
    H: Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    pub leaf: Value<Fp>,
    pub path: Vec<Vec<Value<Fp>>>,
    pub _tree: PhantomData<(H, U, V, W)>,
}

impl<H, U, V, W, const LEAFS: usize> Circuit<Fp> for MerkleCircuit<H, U, V, W, LEAFS>
where
    H: 'static + Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    type Config = MerkleCircuitConfig<H, U, V, W, LEAFS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        MerkleCircuit {
            leaf: Value::unknown(),
            path: storage_proofs_core::halo2::gadgets::por::empty_path::<Fp, U, V, W, LEAFS>(),
            _tree: PhantomData,
        }
    }

    #[allow(clippy::unwrap_used)]
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let (advice_eq, advice_neq, fixed_eq, fixed_neq) = ColumnBuilder::new()
            .with_chip::<UInt32Chip<Fp>>()
            .with_chip::<<H as Halo2Hasher<U>>::Chip>()
            .with_chip::<<H as Halo2Hasher<V>>::Chip>()
            .with_chip::<<H as Halo2Hasher<W>>::Chip>()
            .with_chip::<InsertChip<Fp, U>>()
            .create_columns(meta);

        let uint32 = UInt32Chip::configure(meta, advice_eq[..9].try_into().unwrap());
        let base_hasher =
            <H as Halo2Hasher<U>>::configure(meta, &advice_eq, &advice_neq, &fixed_eq, &fixed_neq);
        let base_insert = InsertChip::configure(meta, &advice_eq, &advice_neq);

        let base_arity = U::to_usize();
        let sub_arity = V::to_usize();
        let top_arity = W::to_usize();

        let sub = if sub_arity == 0 {
            None
        } else if sub_arity == base_arity {
            Some(transmute_arity::<H, U, V>(
                base_hasher.clone(),
                base_insert.clone(),
            ))
        } else {
            let sub_hasher = <H as Halo2Hasher<V>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let sub_insert = InsertChip::configure(meta, &advice_eq, &advice_neq);
            Some((sub_hasher, sub_insert))
        };

        let top = if top_arity == 0 {
            None
        } else if top_arity == base_arity {
            Some(transmute_arity::<H, U, W>(
                base_hasher.clone(),
                base_insert.clone(),
            ))
        } else if top_arity == sub_arity {
            let (sub_hasher, sub_insert) = sub.clone().unwrap();
            Some(transmute_arity::<H, V, W>(sub_hasher, sub_insert))
        } else {
            let top_hasher = <H as Halo2Hasher<W>>::configure(
                meta,
                &advice_eq,
                &advice_neq,
                &fixed_eq,
                &fixed_neq,
            );
            let top_insert = InsertChip::configure(meta, &advice_eq, &advice_neq);
            Some((top_hasher, top_insert))
        };

        let pi = meta.instance_column();
        meta.enable_equality(pi);

        MerkleCircuitConfig {
            uint32,
            base_hasher,
            base_insert,
            sub,
            top,
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

        let MerkleCircuitConfig {
            uint32: uint32_config,
            base_hasher: base_hasher_config,
            base_insert: base_insert_config,
            sub: sub_config,
            top: top_config,
            pi: pi_col,
        } = config;

        let uint32_chip = UInt32Chip::construct(uint32_config);

        <H as Halo2Hasher<U>>::load(&mut layouter, &base_hasher_config)?;
        let base_hasher_chip = <H as Halo2Hasher<U>>::construct(base_hasher_config);
        let base_insert_chip = InsertChip::construct(base_insert_config);

        let sub_chips = sub_config.map(|(hasher_config, insert_config)| {
            let hasher_chip = <H as Halo2Hasher<V>>::construct(hasher_config);
            let insert_chip = InsertChip::construct(insert_config);
            (hasher_chip, insert_chip)
        });

        let top_chips = top_config.map(|(hasher_config, insert_config)| {
            let hasher_chip = <H as Halo2Hasher<W>>::construct(hasher_config);
            let insert_chip = InsertChip::construct(insert_config);
            (hasher_chip, insert_chip)
        });

        let merkle_chip = MerkleChip::<H, U, V, W>::with_subchips(
            base_hasher_chip,
            base_insert_chip,
            sub_chips,
            top_chips,
        );

        let challenge_bits = uint32_chip.pi_assign_bits(
            layouter.namespace(|| "assign challenge pi as 32 bits"),
            pi_col,
            CHALLENGE_ROW,
        )?;

        let root = merkle_chip.compute_root_unassigned_leaf(
            layouter.namespace(|| "compute merkle root"),
            &challenge_bits,
            self.leaf,
            &self.path,
        )?;
        layouter.constrain_instance(root.cell(), pi_col, ROOT_ROW)
    }
}

impl<H, U, V, W, const LEAFS: usize> CircuitRows for MerkleCircuit<H, U, V, W, LEAFS>
where
    H: 'static + Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    fn k(&self) -> u32 {
        let hasher_type = TypeId::of::<H>();
        if hasher_type == TypeId::of::<Sha256Hasher<Fp>>() {
            // TODO (jake): under which arities and tree size does this increase?
            17
        } else if hasher_type == TypeId::of::<PoseidonHasher<Fp>>() {
            use filecoin_hashers::poseidon::PoseidonChip;

            let base_arity = U::to_usize();
            let sub_arity = V::to_usize();
            let top_arity = W::to_usize();

            let base_bit_len = base_arity.trailing_zeros() as usize;
            let sub_bit_len = sub_arity.trailing_zeros() as usize;
            let top_bit_len = top_arity.trailing_zeros() as usize;

            let mut base_challenge_bit_len = LEAFS.trailing_zeros() as usize;
            if sub_arity > 0 {
                base_challenge_bit_len -= sub_bit_len;
            }
            if top_arity > 0 {
                base_challenge_bit_len -= top_bit_len;
            }
            let base_path_len = base_challenge_bit_len / base_bit_len;

            // Four rows for decomposing the challenge into 32 bits.
            let challenge_decomp_rows = 4;
            let base_rows = PoseidonChip::<Fp, U>::num_rows() + InsertChip::<Fp, U>::num_rows();
            let sub_rows = PoseidonChip::<Fp, V>::num_rows() + InsertChip::<Fp, V>::num_rows();
            let top_rows = PoseidonChip::<Fp, W>::num_rows() + InsertChip::<Fp, W>::num_rows();

            let mut rows = challenge_decomp_rows;
            rows += base_path_len * base_rows;
            if sub_arity > 0 {
                rows += sub_rows;
            }
            if top_arity > 0 {
                rows += top_rows;
            };

            (rows as f32).log2().floor() as u32 + 1
        } else {
            unimplemented!("hasher must be poseidon or sha256");
        }
    }
}

impl<H, U, V, W, const LEAFS: usize> MerkleCircuit<H, U, V, W, LEAFS>
where
    H: 'static + Hasher<Field = Fp> + Halo2Hasher<U> + Halo2Hasher<V> + Halo2Hasher<W>,
    U: PoseidonArity<Fp>,
    V: PoseidonArity<Fp>,
    W: PoseidonArity<Fp>,
{
    pub fn new(leaf: Fp, path: Vec<Vec<Fp>>) -> Self {
        MerkleCircuit {
            leaf: Value::known(leaf),
            path: path
                .iter()
                .map(|sibs| sibs.iter().copied().map(Value::known).collect())
                .collect(),
            _tree: PhantomData,
        }
    }
}

#[allow(clippy::unit_arg)]
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
        let merkle_proof = tree
            .gen_proof(CHALLENGE)
            .expect("failed to create merkle proof");

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

        let circ = PoRCircuit::<TreeFr>::new(merkle_proof, false);

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
        let merkle_proof = tree
            .gen_proof(CHALLENGE)
            .expect("failed to create merkle proof");
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
        prover_benchmarks.bench_function("groth16", |b| {
            b.iter(|| {
                black_box(
                    groth16::create_random_proof(groth16_circ.clone(), &groth16_params, &mut rng)
                        .expect("failed to create groth16 proof"),
                )
            })
        });
        prover_benchmarks.bench_function("halo2", |b| {
            b.iter(|| {
                black_box(
                    halo2::create_proof(
                        &halo2_keypair,
                        halo2_circ.clone(),
                        &halo2_pub_inputs,
                        &mut rng,
                    )
                    .expect("failed to create halo2 proof"),
                )
            })
        });
        prover_benchmarks.finish();

        let mut verifier_benchmarks = c.benchmark_group(format!("{}-verifier", benchmark_prefix));
        verifier_benchmarks.sample_size(10);
        verifier_benchmarks.bench_function("groth16", |b| {
            b.iter(|| {
                black_box(
                    groth16::verify_proof(&groth16_vk, &groth16_proof, &groth16_pub_inputs)
                        .expect("failed to verify groth16 proof"),
                )
            })
        });
        verifier_benchmarks.bench_function("halo2", |b| {
            b.iter(|| {
                black_box(
                    halo2::verify_proof(&halo2_keypair, &halo2_proof, &halo2_pub_inputs)
                        .expect("failed to verify halo2 proof"),
                )
            })
        });
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
        prover_benchmarks.bench_function("groth16", |b| {
            b.iter(|| {
                black_box(
                    groth16::create_random_proof_batch(
                        groth16_batch_circs.clone(),
                        &groth16_params,
                        &mut rng,
                    )
                    .expect("failed to create groth16 batch proof"),
                )
            })
        });
        prover_benchmarks.bench_function("halo2", |b| {
            b.iter(|| {
                black_box(
                    halo2::create_batch_proof(
                        &halo2_keypair,
                        &halo2_batch_circs,
                        &halo2_batch_pub_inputs,
                        &mut rng,
                    )
                    .expect("failed to create halo2 batch proof"),
                )
            })
        });
        prover_benchmarks.finish();

        let mut verifier_benchmarks = c.benchmark_group(format!("{}-verifier", benchmark_prefix));
        verifier_benchmarks.sample_size(10);
        verifier_benchmarks.bench_function("groth16", |b| {
            b.iter(|| {
                black_box(
                    groth16::verify_proofs_batch(
                        &groth16_vk,
                        &mut rng,
                        &groth16_batch_proofs,
                        &groth16_batch_pub_inputs,
                    )
                    .expect("failed to verify groth16 batch proof"),
                )
            })
        });
        verifier_benchmarks.bench_function("halo2", |b| {
            b.iter(|| {
                black_box(
                    halo2::verify_proofs(
                        &halo2_keypair,
                        &halo2_batch_proof,
                        &halo2_batch_pub_inputs,
                    )
                    .expect("failed to verify halo2 batch proof"),
                )
            })
        });
        verifier_benchmarks.finish();
    }
}

#[allow(clippy::unit_arg)]
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
        let merkle_proof = tree
            .gen_proof(CHALLENGE)
            .expect("failed to create merkle proof");

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

        let circ = PoRCircuit::<TreeFr>::new(merkle_proof, false);

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
        let merkle_proof = tree
            .gen_proof(CHALLENGE)
            .expect("failed to create merkle proof");
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
    prover_benchmarks.bench_function("groth16", |b| {
        b.iter(|| {
            black_box(
                groth16::create_random_proof(groth16_circ.clone(), &groth16_params, &mut rng)
                    .expect("failed to create groth16 proof"),
            )
        })
    });
    prover_benchmarks.finish();
    // Only benchmark halo2 once because it takes a long time to run.
    {
        let start = Instant::now();
        black_box(
            halo2::create_proof(&halo2_keypair, halo2_circ, &halo2_pub_inputs, &mut rng)
                .expect("failed to create halo2 proof"),
        );
        println!("\n{}-prover/halo2", benchmark_prefix);
        println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
    }

    let mut verifier_benchmarks = c.benchmark_group(format!("{}-verifier", benchmark_prefix));
    verifier_benchmarks.sample_size(10);
    verifier_benchmarks.bench_function("groth16", |b| {
        b.iter(|| {
            black_box(
                groth16::verify_proof(&groth16_vk, &groth16_proof, &groth16_pub_inputs)
                    .expect("failed to verify groth16 proof"),
            )
        })
    });
    verifier_benchmarks.finish();
    // Only benchmark halo2 once because it takes a long time to run.
    {
        let start = Instant::now();
        black_box(
            halo2::verify_proof(&halo2_keypair, &halo2_proof, &halo2_pub_inputs)
                .expect("failed to verify halo2 proof"),
        );
        println!("\n{}-verifier/halo2", benchmark_prefix);
        println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
    }
}

criterion_group!(
    benches,
    bench_groth16_halo2_poseidon,
    bench_groth16_halo2_sha256_arity_2,
);
criterion_main!(benches);
