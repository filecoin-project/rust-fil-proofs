#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion, ParameterizedBenchmark};
use storage_proofs::drgraph::*;
use storage_proofs::hasher::pedersen::*;

fn drgraph(c: &mut Criterion) {
    let params: Vec<_> = vec![12, 24, 128, 1024]
        .iter()
        .map(|n| (BucketGraph::<PedersenHasher>::new(*n, 6, 0, new_seed()), 2))
        .collect();
    c.bench(
        "sample",
        ParameterizedBenchmark::new(
            "bucket/m=6",
            |b, (graph, i)| {
                b.iter(|| {
                    let mut parents = vec![0; 6];
                    black_box(graph.parents(*i, &mut parents));
                })
            },
            params,
        ),
    );
}

criterion_group!(benches, drgraph);
criterion_main!(benches);
