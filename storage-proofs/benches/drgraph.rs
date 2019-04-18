#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion, ParameterizedBenchmark};
use storage_proofs::drgraph::*;
use storage_proofs::hasher::pedersen::*;

fn drgraph(c: &mut Criterion) {
    let params: Vec<_> = vec![12, 24, 128, 1024];
    c.bench(
        "drgraph",
        ParameterizedBenchmark::new(
            "parents/bucket/m=6",
            |b, n| {
                let i = 2;
                let graph = BucketGraph::<PedersenHasher>::new(*n, 6, 0, new_seed());
                b.iter(|| {
                    let mut parents = vec![0; 6];
                    black_box(graph.parents(i, &mut parents));
                })
            },
            params,
        ),
    );
}

criterion_group!(benches, drgraph);
criterion_main!(benches);
