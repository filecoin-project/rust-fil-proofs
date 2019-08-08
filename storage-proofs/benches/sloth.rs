#[macro_use]
extern crate criterion;

use bellperson::groth16::*;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use criterion::{black_box, Benchmark, Criterion};
use fil_sapling_crypto::circuit::num;
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};
use rand::{thread_rng, Rng};
use storage_proofs::circuit::bench::BenchCS;

use storage_proofs::circuit;
use storage_proofs::crypto::sloth;

struct SlothExample<E: JubjubEngine> {
    key: Option<E::Fr>,
    ciphertext: Option<E::Fr>,
}

impl<E: JubjubEngine> Circuit<E> for SlothExample<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let key_num = num::AllocatedNum::alloc(cs.namespace(|| "sloth-key"), || {
            Ok(self.key.ok_or_else(|| SynthesisError::AssignmentMissing)?)
        })?;
        let res = circuit::sloth::decode(cs.namespace(|| "sloth"), &key_num, self.ciphertext)?;
        // please compiler don't optimize the result away
        // only check if we actually have input data
        if self.ciphertext.is_some() {
            res.get_value().unwrap();
        }

        Ok(())
    }
}

fn sloth_benchmark(c: &mut Criterion) {
    c.bench(
        "sloth",
        Benchmark::new("decode-non-circuit", |b| {
            let mut rng = thread_rng();
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();
            let ciphertext = sloth::encode::<Bls12>(&key, &plaintext);

            b.iter(|| black_box(sloth::decode::<Bls12>(&key, &ciphertext)))
        })
        .with_function("decode-circuit-create_proof", move |b| {
            let mut rng = thread_rng();
            let groth_params = generate_random_parameters::<Bls12, _, _>(
                SlothExample {
                    key: None,
                    ciphertext: None,
                },
                &mut rng,
            )
            .unwrap();

            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();
            let ciphertext = sloth::encode::<Bls12>(&key, &plaintext);

            b.iter(|| {
                let proof = create_random_proof(
                    SlothExample {
                        key: Some(key),
                        ciphertext: Some(ciphertext),
                    },
                    &groth_params,
                    &mut rng,
                )
                .unwrap();

                black_box(proof)
            });
        })
        .with_function("decode-circuit-synthesize_circuit", move |b| {
            let mut rng = thread_rng();
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();
            let ciphertext = sloth::encode::<Bls12>(&key, &plaintext);

            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();

                SlothExample {
                    key: Some(key),
                    ciphertext: Some(ciphertext),
                }
                .synthesize(&mut cs)
                .unwrap();

                black_box(cs)
            });
        })
        .with_function("encode-non-circuit", move |b| {
            let mut rng = thread_rng();
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();

            b.iter(|| black_box(sloth::encode::<Bls12>(&key, &plaintext)))
        })
        .sample_size(20),
    );
}

criterion_group!(benches, sloth_benchmark);
criterion_main!(benches);
