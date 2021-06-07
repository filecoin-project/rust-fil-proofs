use bellperson::{
    bls::Bls12,
    gadgets::boolean::{AllocatedBit, Boolean},
    groth16::{create_random_proof, generate_random_parameters},
    util_cs::bench_cs::BenchCS,
    Circuit, ConstraintSystem, SynthesisError,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use storage_proofs_core::{crypto::xor, gadgets::xor::xor as xor_circuit};

struct XorExample<'a> {
    key: &'a [Option<bool>],
    data: &'a [Option<bool>],
}

impl<'a> Circuit<Bls12> for XorExample<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let key: Vec<Boolean> = self
            .key
            .iter()
            .enumerate()
            .map(|(i, b)| {
                Ok(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("key_bit {}", i)),
                    *b,
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        let data: Vec<Boolean> = self
            .data
            .iter()
            .enumerate()
            .map(|(i, b)| {
                Ok(Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("data_bit {}", i)),
                    *b,
                )?))
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let mut cs = cs.namespace(|| "xor");
        let _res = xor_circuit(&mut cs, &key, &data)?;

        Ok(())
    }
}

fn xor_benchmark(c: &mut Criterion) {
    let params = vec![32, 64, 10 * 32];

    let mut group = c.benchmark_group("xor");
    for bytes in params {
        group.bench_function(format!("non-circuit-{}", bytes), |b| {
            let mut rng = thread_rng();
            let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            let data: Vec<u8> = (0..bytes).map(|_| rng.gen()).collect();

            b.iter(|| black_box(xor::encode(&key, &data)))
        });
    }

    group.finish();
}

fn xor_circuit_benchmark(c: &mut Criterion) {
    let mut rng1 = thread_rng();
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        XorExample {
            key: &[None; 8 * 32],
            data: &[None; 256],
        },
        &mut rng1,
    )
    .unwrap();

    let params = vec![32];

    let mut group = c.benchmark_group("xor-circuit");
    for bytes in params {
        group.bench_function(format!("create-proof-{}", bytes), |b| {
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
        });
        group.bench_function(format!("synthesize-{}", bytes), |b| {
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
        });
    }

    group.sample_size(20);
    group.finish();
}

criterion_group!(benches, xor_benchmark, xor_circuit_benchmark);
criterion_main!(benches);
