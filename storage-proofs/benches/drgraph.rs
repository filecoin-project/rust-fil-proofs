use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use storage_proofs::drgraph::*;
use storage_proofs::hasher::pedersen::*;

fn drgraph(c: &mut Criterion) {
    let params: Vec<_> = vec![12, 24, 128, 1024]
        .iter()
        .map(|n| {
            (
                BucketGraph::<PedersenHasher>::new(*n, BASE_DEGREE, 0, new_seed()).unwrap(),
                2,
            )
        })
        .collect();
    c.bench(
        "sample",
        ParameterizedBenchmark::new(
            "bucket/m=6",
            |b, (graph, i)| {
                b.iter(|| {
                    let mut parents = vec![0; 6];
                    black_box(graph.parents(*i, &mut parents).unwrap());
                })
            },
            params,
        ),
    );
}

criterion_group!(benches, drgraph);
criterion_main!(benches);
