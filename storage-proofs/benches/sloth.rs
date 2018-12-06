#[macro_use]
extern crate criterion;
extern crate bellman;
extern crate bitvec;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate storage_proofs;

use bellman::groth16::*;
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use criterion::{black_box, Criterion, ParameterizedBenchmark};
use pairing::bls12_381::{Bls12, Fr};
use rand::{thread_rng, Rng};
use sapling_crypto::circuit::num;
use sapling_crypto::jubjub::JubjubEngine;
use storage_proofs::circuit::bench::BenchCS;

use storage_proofs::circuit;
use storage_proofs::crypto::sloth;

struct SlothExample<E: JubjubEngine> {
    key: Option<E::Fr>,
    ciphertext: Option<E::Fr>,
    rounds: usize,
}

impl<E: JubjubEngine> Circuit<E> for SlothExample<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let key_num = num::AllocatedNum::alloc(cs.namespace(|| "sloth-key"), || {
            Ok(self.key.ok_or_else(|| SynthesisError::AssignmentMissing)?)
        })?;
        let res = circuit::sloth::decode(
            cs.namespace(|| "sloth"),
            &key_num,
            self.ciphertext,
            self.rounds,
        )?;
        // please compiler don't optimize the result away
        // only check if we actually have input data
        if self.ciphertext.is_some() {
            res.get_value().unwrap();
        }

        Ok(())
    }
}

fn sloth_benchmark(c: &mut Criterion) {
    let params = vec![1, 4, 8];

    c.bench(
        "sloth",
        ParameterizedBenchmark::new(
            "decode-non-circuit",
            |b, rounds| {
                let mut rng = thread_rng();
                let key: Fr = rng.gen();
                let plaintext: Fr = rng.gen();
                let ciphertext = sloth::encode::<Bls12>(&key, &plaintext, *rounds);

                b.iter(|| black_box(sloth::decode::<Bls12>(&key, &ciphertext, *rounds)))
            },
            params,
        )
        .with_function("decode-circuit-create_proof", move |b, rounds| {
            let mut rng = thread_rng();
            let groth_params = generate_random_parameters::<Bls12, _, _>(
                SlothExample {
                    key: None,
                    ciphertext: None,
                    rounds: *rounds,
                },
                &mut rng,
            )
            .unwrap();

            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();
            let ciphertext = sloth::encode::<Bls12>(&key, &plaintext, *rounds);

            b.iter(|| {
                let proof = create_random_proof(
                    SlothExample {
                        key: Some(key),
                        ciphertext: Some(ciphertext),
                        rounds: *rounds,
                    },
                    &groth_params,
                    &mut rng,
                )
                .unwrap();

                black_box(proof)
            });
        })
        .with_function("decode-circuit-synthesize_circuit", move |b, rounds| {
            let mut rng = thread_rng();
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();
            let ciphertext = sloth::encode::<Bls12>(&key, &plaintext, *rounds);

            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();

                SlothExample {
                    key: Some(key),
                    ciphertext: Some(ciphertext),
                    rounds: *rounds,
                }
                .synthesize(&mut cs)
                .unwrap();

                black_box(cs)
            });
        })
        .with_function("encode-non-circuit", move |b, rounds| {
            let mut rng = thread_rng();
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();

            b.iter(|| black_box(sloth::encode::<Bls12>(&key, &plaintext, *rounds)))
        })
        .sample_size(20),
    );
}

criterion_group!(benches, sloth_benchmark);
criterion_main!(benches);
