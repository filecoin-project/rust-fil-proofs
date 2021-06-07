use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filecoin_hashers::poseidon::PoseidonHasher;
use storage_proofs_core::{
    api_version::ApiVersion,
    drgraph::{BucketGraph, Graph, BASE_DEGREE},
};

#[allow(clippy::unit_arg)]
fn drgraph(c: &mut Criterion) {
    let params = vec![12, 24, 128, 1024];

    let mut group = c.benchmark_group("sample");
    for n in params {
        group.bench_function(format!("bucket/m=6-{}", n), |b| {
            let graph =
                BucketGraph::<PoseidonHasher>::new(n, BASE_DEGREE, 0, [32; 32], ApiVersion::V1_1_0)
                    .unwrap();

            b.iter(|| {
                let mut parents = vec![0; 6];
                black_box(graph.parents(2, &mut parents).unwrap());
            })
        });
    }

    group.finish();
}

criterion_group!(benches, drgraph);
criterion_main!(benches);
