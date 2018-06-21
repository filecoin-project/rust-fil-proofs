#[macro_use]
extern crate criterion;
extern crate proofs;

use criterion::Criterion;
use proofs::crypto::pedersen;
use proofs::util::bytes_into_bits;

fn pedersen_benchmark(c: &mut Criterion) {
    c.bench_function("pedersen_compression", |b| {
        b.iter(|| pedersen::pedersen_compression(&bytes_into_bits(b"some bytes")))
    });
}

criterion_group!(benches, pedersen_benchmark);
criterion_main!(benches);
