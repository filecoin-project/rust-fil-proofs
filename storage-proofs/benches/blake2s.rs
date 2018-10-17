#[macro_use]
extern crate criterion;
extern crate bellman;
extern crate bitvec;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sha2;
extern crate storage_proofs;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use criterion::{black_box, Criterion, ParameterizedBenchmark};
use pairing::bls12_381::Bls12;
use rand::{thread_rng, Rng};
use sapling_crypto::circuit as scircuit;
use sapling_crypto::circuit::boolean::{self, Boolean};
use sapling_crypto::jubjub::JubjubEngine;
use storage_proofs::circuit::bench::BenchCS;
use storage_proofs::crypto;

struct Blake2sExample<'a> {
    data: &'a [Option<bool>],
}

impl<'a, E> Circuit<E> for Blake2sExample<'a>
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

        let cs = cs.namespace(|| "blake2s");
        let personalization = vec![0u8; 8];
        let _res = scircuit::blake2s::blake2s(cs, &data, &personalization)?;
        Ok(())
    }
}

fn blake2s_benchmark(c: &mut Criterion) {
    let mut rng1 = thread_rng();
    let rng2 = thread_rng();

    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Blake2sExample {
            data: &vec![None; 256],
        },
        &mut rng1,
    )
    .unwrap();

    let params = vec![32];

    c.bench(
        "blake2s",
        ParameterizedBenchmark::new(
            "non-circuit-32bytes",
            |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

                b.iter(|| crypto::blake2s::blake2s(&data))
            },
            params,
        )
        .with_function("circuit-32bytes-create_proof", move |b, bytes| {
            b.iter(|| {
                let mut rng = rng1.clone();
                let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

                let proof = create_random_proof(
                    Blake2sExample {
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

                Blake2sExample {
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

criterion_group!(benches, blake2s_benchmark);
criterion_main!(benches);
