use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use storage_proofs::drgraph::*;
use storage_proofs::hasher::pedersen::*;

fn drgraph(c: &mut Criterion) {
    let params = vec![12, 24, 128, 1024];

    c.bench(
        "sample",
        ParameterizedBenchmark::new(
            "bucket/m=6",
            |b, n| {
                let graph =
                    BucketGraph::<PedersenHasher>::new(*n, BASE_DEGREE, 0, new_seed()).unwrap();

                b.iter(|| {
                    let mut parents = vec![0; 6];
                    black_box(graph.parents(2, &mut parents).unwrap());
                })
            },
            params,
        ),
    );
}

criterion_group!(benches, drgraph);
criterion_main!(benches);
