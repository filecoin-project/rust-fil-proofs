#[macro_use]
extern crate criterion;
extern crate proofs;

use criterion::{black_box, Criterion, ParameterizedBenchmark};
use proofs::drgraph::*;

fn drgraph(c: &mut Criterion) {
    let params: Vec<usize> = vec![12, 24, 128, 1024];
    c.bench(
        "sample",
        ParameterizedBenchmark::new(
            "bucket/m=6",
            |b, i| {
                b.iter(|| {
                    black_box(Graph::new(*i, Some(Sampling::Bucket(6))));
                })
            },
            params,
        ).with_function("dr", |b, i| {
            b.iter(|| {
                black_box(Graph::new(*i, Some(Sampling::DR)));
            })
        }),
    );
}

criterion_group!(benches, drgraph);
criterion_main!(benches);
