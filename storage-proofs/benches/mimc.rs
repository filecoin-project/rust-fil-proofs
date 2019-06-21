#[macro_use]
extern crate criterion;

use bellperson::groth16::*;
use bellperson::Circuit;
use criterion::{black_box, Criterion, ParameterizedBenchmark};
use paired::bls12_381::Bls12;
use rand::{thread_rng, Rng};
use storage_proofs::circuit::bench::BenchCS;

use storage_proofs::circuit;
use storage_proofs::crypto::mimc;

fn mimc_benchmark(c: &mut Criterion) {
    // let params = vec![32, 64, 10 * 32];
    let params = vec![32];

    c.bench(
        "hash-mimc",
        ParameterizedBenchmark::new(
            "non-circuit",
            |b, _bytes| {
                let mut rng = thread_rng();
                let constants = (0..mimc::MIMC_ROUNDS)
                    .map(|_| rng.gen())
                    .collect::<Vec<_>>();

                // TODO: actually do a byte construction
                let (xl, xr) = rng.gen();

                b.iter(|| black_box(mimc::mimc::<Bls12>(xl, xr, &constants)))
            },
            params,
        ),
    );
}

fn mimc_circuit_benchmark(c: &mut Criterion) {
    let mut rng = thread_rng();
    let constants = (0..mimc::MIMC_ROUNDS)
        .map(|_| rng.gen())
        .collect::<Vec<_>>();

    let groth_params = generate_random_parameters::<Bls12, _, _>(
        circuit::mimc::MiMC::<Bls12> {
            xl: None,
            xr: None,
            constants: &constants,
        },
        &mut rng,
    )
    .unwrap();

    let params = vec![32];

    let constants1 = constants.clone();
    let constants2 = constants.clone();

    c.bench(
        "hash-mimc-circuit",
        ParameterizedBenchmark::new(
            "create-proof",
            move |b, _bytes| {
                let mut rng = thread_rng();
                let (xl, xr) = rng.gen();

                b.iter(|| {
                    let proof = create_random_proof(
                        circuit::mimc::MiMC {
                            xl: Some(xl),
                            xr: Some(xr),
                            constants: &constants1,
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
        .with_function("synthesize", move |b, _bytes| {
            let mut rng = thread_rng();
            let (xl, xr) = rng.gen();

            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();
                circuit::mimc::MiMC {
                    xl: Some(xl),
                    xr: Some(xr),
                    constants: &constants2,
                }
                .synthesize(&mut cs)
                .unwrap();

                black_box(cs)
            });
        })
        .sample_size(20),
    );
}

criterion_group!(benches, mimc_benchmark, mimc_circuit_benchmark);
criterion_main!(benches);
