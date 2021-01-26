use bellperson::{
    bls::Bls12,
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        sha256::sha256 as sha256_circuit,
    },
    groth16::{create_random_proof, generate_random_parameters},
    util_cs::bench_cs::BenchCS,
    Circuit, ConstraintSystem, SynthesisError,
};
use criterion::{
    black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark, Throughput,
};
use rand::{thread_rng, Rng};
use sha2::Digest;

struct Sha256Example<'a> {
    data: &'a [Option<bool>],
}

impl<'a> Circuit<Bls12> for Sha256Example<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let data: Vec<Boolean> = self
            .data
            .iter()
            .enumerate()
            .map(|(i, b)| {
                Ok(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", i)),
                    *b,
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let cs = cs.namespace(|| "sha256");

        let _res = sha256_circuit(cs, &data)?;
        Ok(())
    }
}

fn sha256_benchmark(c: &mut Criterion) {
    let params = vec![32, 64, 10 * 32, 37 * 32];

    c.bench(
        "hash-sha256-base",
        ParameterizedBenchmark::new(
            "non-circuit",
            |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();

                b.iter(|| black_box(sha2::Sha256::digest(&data)))
            },
            params,
        )
        .throughput(|bytes| Throughput::Bytes(*bytes as u64)),
    );
}

fn sha256_raw_benchmark(c: &mut Criterion) {
    let params = vec![64, 10 * 32, 38 * 32];

    c.bench(
        "hash-sha256-raw",
        ParameterizedBenchmark::new(
            "non-circuit",
            |b, bytes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();
                let chunks = data.chunks(32).collect::<Vec<_>>();

                b.iter(|| black_box(sha2raw::Sha256::digest(&chunks)))
            },
            params,
        )
        .throughput(|bytes| Throughput::Bytes(*bytes as u64)),
    );
}

fn sha256_circuit_benchmark(c: &mut Criterion) {
    let mut rng1 = thread_rng();

    let params = vec![32, 64];

    c.bench(
        "hash-sha256-circuit",
        ParameterizedBenchmark::new(
            "create-proof",
            move |b, bytes| {
                let groth_params = generate_random_parameters::<Bls12, _, _>(
                    Sha256Example {
                        data: &vec![None; *bytes as usize * 8],
                    },
                    &mut rng1,
                )
                .unwrap();

                let mut rng = thread_rng();
                let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

                b.iter(|| {
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
            },
            params,
        )
        .with_function("synthesize", move |b, bytes| {
            let mut rng = thread_rng();
            let data: Vec<Option<bool>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();
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

criterion_group!(
    benches,
    sha256_benchmark,
    sha256_raw_benchmark,
    sha256_circuit_benchmark
);
criterion_main!(benches);
