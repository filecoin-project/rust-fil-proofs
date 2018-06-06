#[macro_use]
extern crate criterion;
extern crate proofs;

use criterion::Criterion;
use proofs::crypto::pedersen;

fn pedersen_benchmark(c: &mut Criterion) {
    c.bench_function("pedersen_jub_jub_internal", |b| {
        b.iter(|| pedersen::pedersen_jubjub_internal(0, b"some bytes"))
    });
}

criterion_group!(benches, pedersen_benchmark);
criterion_main!(benches);
