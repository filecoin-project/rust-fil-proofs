#[macro_use]
extern crate criterion;

use algebra::curves::bls12_381::Bls12_381 as Bls12;
use criterion::{black_box, Criterion, ParameterizedBenchmark};
use dpc::gadgets::Assignment;
use rand::{thread_rng, Rng};
use snark::groth16::{create_random_proof, generate_random_parameters};
use snark::{Circuit, ConstraintSystem, SynthesisError};
use snark_gadgets::bits::uint8::UInt8;
use snark_gadgets::fields::FieldGadget;
use snark_gadgets::utils::AllocGadget;
use storage_proofs::circuit;
use storage_proofs::circuit::bench::BenchCS;
use storage_proofs::crypto::pedersen;
use storage_proofs::singletons::PEDERSEN_PARAMS;

struct PedersenExample<'a> {
    data: &'a [Option<u8>],
}

impl<'a> Circuit<Bls12> for PedersenExample<'a> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let data: Vec<UInt8> = self
            .data
            .into_iter()
            .enumerate()
            .map(|(i, b)| UInt8::alloc(cs.ns(|| format!("bit {}", i)), || b.get()))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        let cs = cs.ns(|| "pedersen");
        let res = circuit::pedersen::pedersen_compression_num(cs, &data, &PEDERSEN_PARAMS)?;
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
    let mut rng1 = thread_rng();
    let groth_params = generate_random_parameters::<Bls12, _, _>(
        PedersenExample {
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
                let data: Vec<Option<u8>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

                b.iter(|| {
                    let proof = create_random_proof(
                        PedersenExample {
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
            let data: Vec<Option<u8>> = (0..bytes * 8).map(|_| Some(rng.gen())).collect();

            b.iter(|| {
                let mut cs = BenchCS::<Bls12>::new();
                PedersenExample {
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
