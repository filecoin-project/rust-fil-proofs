#[macro_use]
extern crate criterion;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use criterion::{black_box, Criterion, ParameterizedBenchmark};
use pairing::bls12_381::Bls12;
use rand::{thread_rng, Rng};
use sapling_crypto::circuit as scircuit;
use sapling_crypto::circuit::boolean::{self, Boolean};
use sapling_crypto::jubjub::JubjubEngine;
use storage_proofs::circuit::bench::BenchCS;

use sha2::{Digest, Sha256};

struct Sha256Example<'a> {
    data: &'a [Option<bool>],
}

impl<'a, E> Circuit<E> for Sha256Example<'a>
where
    E: JubjubEngine,
{
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let data: Vec<Boolean> = self
            .data
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Ok(Boolean::from(boolean::AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    *b,
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let cs = cs.namespace(|| "sha256");

        let _res = scircuit::sha256::sha256(cs, &data)?;
        Ok(())
    }
}

fn sha256_benchmark(c: &mut Criterion) {
    let mut rng1 = thread_rng();
    let rng2 = thread_rng();

    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Sha256Example {
            data: &vec![None; 256],
        },
        &mut rng1,
    )
    .unwrap();

    let params = vec![32];

    c.bench(
        "sha256",
        ParameterizedBenchmark::new(
            "non-circuit-32bytes",
            |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

                b.iter(|| black_box(Sha256::digest(&data)))
            },
            params,
        )
        .with_function("circuit-32bytes-create_proof", move |b, bytes| {
            b.iter(|| {
                let mut rng = rng1.clone();
                let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

                let proof = create_random_proof(
                    Sha256Example {
                        data: data.as_slice(),
                    },
                    &groth_params,
                    &mut rng,
                )
                .unwrap();

                black_box(proof)
            });
        })
        .with_function("circuit-32bytes-synthesize_circuit", move |b, bytes| {
            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();

                let mut rng = rng2.clone();
                let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

                Sha256Example {
                    data: data.as_slice(),
                }
                .synthesize(&mut cs)
                .unwrap();

                black_box(cs)
            });
        })
        .sample_size(20),
    );
}

criterion_group!(benches, sha256_benchmark);
criterion_main!(benches);
