#[macro_use]
extern crate criterion;

use algebra::curves::bls12_377::Bls12_377 as Bls12;
use criterion::{black_box, Criterion, ParameterizedBenchmark};
use dpc::gadgets::prf::blake2s::blake2s_gadget;
use dpc::gadgets::Assignment;
use rand::{thread_rng, Rng};
use snark::groth16::{create_random_proof, generate_random_parameters};
use snark::{Circuit, ConstraintSystem, SynthesisError};
use snark_gadgets::boolean::{self, Boolean};
use snark_gadgets::utils::AllocGadget;
use storage_proofs::circuit::bench::BenchCS;

struct Blake2sExample<'a> {
    data: &'a [Option<bool>],
}

impl<'a> Circuit<Bls12> for Blake2sExample<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let data: Vec<Boolean> = self
            .data
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Ok(Boolean::from(boolean::AllocatedBit::alloc(
                    cs.ns(|| format!("bit {}", i)),
                    || b.get(),
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let cs = cs.ns(|| "blake2s");
        let _res = blake2s_gadget(cs, &data)?;
        Ok(())
    }
}

fn blake2s_benchmark(c: &mut Criterion) {
    let params = vec![32, 64, 10 * 32];

    c.bench(
        "hash-blake2s",
        ParameterizedBenchmark::new(
            "non-circuit",
            |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

                b.iter(|| black_box(blake2s_simd::blake2s(&data)))
            },
            params,
        ),
    );
}

fn blake2s_circuit_benchmark(c: &mut Criterion) {
    let mut rng1 = thread_rng();
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Blake2sExample {
            data: &vec![None; 256],
        },
        &mut rng1,
    )
    .unwrap();

    let params = vec![32];

    c.bench(
        "hash-blake2s-circuit",
        ParameterizedBenchmark::new(
            "create-proof",
            move |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

                b.iter(|| {
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
            },
            params,
        )
        .with_function("synthesize", move |b, bytes| {
            let mut rng = thread_rng();
            let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();
            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();

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

criterion_group!(benches, blake2s_benchmark, blake2s_circuit_benchmark);
criterion_main!(benches);
