use bellperson::bls::Bls12;
use bellperson::gadgets::boolean::{self, Boolean};
use bellperson::groth16::*;
use bellperson::util_cs::bench_cs::BenchCS;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use rand::{thread_rng, Rng};

struct Blake2sExample<'a> {
    data: &'a [Option<bool>],
}

impl<'a> Circuit<Bls12> for Blake2sExample<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let data: Vec<Boolean> = self
            .data
            .iter()
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
        let _res = bellperson::gadgets::blake2s::blake2s(cs, &data, &personalization)?;
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
    let groth_params =
        generate_random_parameters::<Bls12, _, _>(Blake2sExample { data: &[None; 256] }, &mut rng1)
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
