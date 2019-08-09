#[macro_use]
extern crate criterion;

use algebra::curves::bls12_381::Bls12_381 as Bls12;
use criterion::{black_box, Criterion, ParameterizedBenchmark};
use dpc::gadgets::Assignment;
use rand::{thread_rng, Rng};
use snark::groth16::{create_random_proof, generate_random_parameters};
use snark::{Circuit, ConstraintSystem, SynthesisError};
use snark_gadgets::boolean::{AllocatedBit, Boolean};
use snark_gadgets::utils::AllocGadget;
use storage_proofs::circuit;
use storage_proofs::circuit::bench::BenchCS;
use storage_proofs::crypto::xor;

struct XorExample<'a> {
    key: &'a [Option<bool>],
    data: &'a [Option<bool>],
}

impl<'a> Circuit<Bls12> for XorExample<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let key: Vec<Boolean> = self
            .key
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Ok(Boolean::from(AllocatedBit::alloc(
                    cs.ns(|| format!("key_bit {}", i)),
                    || b.get(),
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        let data: Vec<Boolean> = self
            .data
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                Ok(Boolean::from(AllocatedBit::alloc(
                    cs.ns(|| format!("data_bit {}", i)),
                    || b.get(),
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let mut cs = cs.ns(|| "xor");
        let _res = circuit::xor::xor(&mut cs, &key, &data)?;

        Ok(())
    }
}

fn xor_benchmark(c: &mut Criterion) {
    let params = vec![32, 64, 10 * 32];

    c.bench(
        "xor",
        ParameterizedBenchmark::new(
            "non-circuit",
            |b, bytes| {
                let mut rng = thread_rng();
                let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
                let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

                b.iter(|| black_box(xor::encode(&key, &data)))
            },
            params,
        ),
    );
}

fn xor_circuit_benchmark(c: &mut Criterion) {
    let mut rng1 = thread_rng();
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        XorExample {
            key: &vec![None; 8 * 32],
            data: &vec![None; 256],
        },
        &mut rng1,
    )
    .unwrap();

    let params = vec![32];

    c.bench(
        "xor-circuit",
        ParameterizedBenchmark::new(
            "create-proof",
            move |b, bytes| {
                let mut rng = thread_rng();
                let key: Vec<Option<bool>> = (0..32 * 8).map(|_| Some(rng.gen())).collect();
                let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

                b.iter(|| {
                    let proof = create_random_proof(
                        XorExample {
                            key: key.as_slice(),
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
            let key: Vec<Option<bool>> = (0..32 * 8).map(|_| Some(rng.gen())).collect();
            let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();
                XorExample {
                    key: key.as_slice(),
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

criterion_group!(benches, xor_benchmark, xor_circuit_benchmark);
criterion_main!(benches);
