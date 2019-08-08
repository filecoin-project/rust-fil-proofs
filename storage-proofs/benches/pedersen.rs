#[macro_use]
extern crate criterion;

use bellperson::groth16::*;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use criterion::{black_box, Criterion, ParameterizedBenchmark};
use fil_sapling_crypto::circuit::boolean::{self, Boolean};
use fil_sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};
use paired::bls12_381::Bls12;
use rand::{thread_rng, Rng};
use storage_proofs::circuit::bench::BenchCS;

use storage_proofs::circuit;
use storage_proofs::crypto::pedersen;
use storage_proofs::settings;

struct PedersenExample<'a, E: JubjubEngine> {
    params: &'a E::Params,
    data: &'a [Option<bool>],
}

impl<'a, E: JubjubEngine> Circuit<E> for PedersenExample<'a, E> {
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

        let cs = cs.namespace(|| "pedersen");
        let res = circuit::pedersen::pedersen_compression_num(cs, self.params, &data)?;
        // please compiler don't optimize the result away
        // only check if we actually have input data
        if self.data[0].is_some() {
            res.get_value().unwrap();
        }

        Ok(())
    }
}

fn pedersen_benchmark(c: &mut Criterion) {
    let params = vec![32, 64, 10 * 32];

    c.bench(
        "hash-pedersen",
        ParameterizedBenchmark::new(
            "non-circuit",
            |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

                if *bytes > 64 {
                    b.iter(|| black_box(pedersen::pedersen_md_no_padding(&data)))
                } else {
                    b.iter(|| black_box(pedersen::pedersen(&data)))
                }
            },
            params,
        ),
    );
}

fn pedersen_circuit_benchmark(c: &mut Criterion) {
    let window_size = settings::SETTINGS
        .lock()
        .unwrap()
        .pedersen_hash_exp_window_size;
    let jubjub_params = JubjubBls12::new_with_window_size(window_size);
    let jubjub_params2 = JubjubBls12::new_with_window_size(window_size);
    let mut rng1 = thread_rng();
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        PedersenExample {
            params: &jubjub_params,
            data: &vec![None; 256],
        },
        &mut rng1,
    )
    .unwrap();

    let params = vec![32];

    c.bench(
        "hash-pedersen-circuit",
        ParameterizedBenchmark::new(
            "create-proof",
            move |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

                b.iter(|| {
                    let proof = create_random_proof(
                        PedersenExample {
                            params: &jubjub_params,
                            data: data.as_slice(),
                        },
                        &groth_params,
                        &mut rng,
                    )
                    .unwrap();

                    black_box(proof)
                });
            },
            params,
        )
        .with_function("synthesize", move |b, bytes| {
            let mut rng = thread_rng();
            let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();
                PedersenExample {
                    params: &jubjub_params2,
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

criterion_group!(benches, pedersen_benchmark, pedersen_circuit_benchmark);
criterion_main!(benches);
