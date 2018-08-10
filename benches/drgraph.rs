#[macro_use]
extern crate criterion;
extern crate proofs;

use criterion::{black_box, Criterion, ParameterizedBenchmark};
use proofs::drgraph::*;

fn drgraph(c: &mut Criterion) {
    let params: Vec<_> = vec![12, 24, 128, 1024]
        .iter()
        .map(|n| (BucketGraph::new(*n, 6, new_seed()), 2))
        .collect();
    c.bench(
        "sample",
        ParameterizedBenchmark::new(
            "bucket/m=6",
            |b, (graph, i)| {
                b.iter(|| {
                    black_box(graph.parents(*i));
                })
            },
            params,
        ),
    );
}

criterion_group!(benches, drgraph);
criterion_main!(benches);
