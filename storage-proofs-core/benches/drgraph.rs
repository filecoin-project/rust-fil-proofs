use blstrs::Scalar as Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filecoin_hashers::{poseidon::PoseidonHasher, Hasher};
use pasta_curves::{Fp, Fq};
use storage_proofs_core::{
    api_version::ApiVersion,
    drgraph::{BucketGraph, Graph, BASE_DEGREE},
};

#[allow(clippy::unit_arg)]
fn bench_for_hasher<H: Hasher>(c: &mut Criterion, hasher_name: &str) {
    // Graph sizes to bench.
    let nodes = vec![12, 24, 128, 1024];

    // The node to generate parents for; DRG parent-gen for the first and second nodes (node
    // indexes `0` and `1`) is different than parent-gen for all other nodes (node-indexes `>= 2`).
    let child: usize = 2;

    let mut group = c.benchmark_group("drg-parent-gen");
    for n in nodes {
        group.bench_function(
            format!("deg={}-nodes={}-{}", BASE_DEGREE, n, hasher_name),
            |b| {
                let graph =
                    BucketGraph::<H>::new(n, BASE_DEGREE, 0, [32; 32], ApiVersion::V1_1_0).unwrap();

                b.iter(|| {
                    let mut parents = vec![0; BASE_DEGREE];
                    black_box(graph.parents(child, &mut parents).unwrap());
                })
            },
        );
    }

    group.finish();
}

#[allow(clippy::unit_arg)]
fn drgraph(c: &mut Criterion) {
    bench_for_hasher::<PoseidonHasher<Fr>>(c, "bls");
    bench_for_hasher::<PoseidonHasher<Fp>>(c, "pallas");
    bench_for_hasher::<PoseidonHasher<Fq>>(c, "vesta");
}

criterion_group!(benches, drgraph);
criterion_main!(benches);
