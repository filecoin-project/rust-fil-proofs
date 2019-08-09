#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion, ParameterizedBenchmark};
use rand::{thread_rng, Rng};
use storage_proofs_zexe::drgraph::{new_seed, Graph};
use storage_proofs_zexe::hasher::{Blake2sHasher, PedersenHasher};
use storage_proofs_zexe::zigzag_graph::{ZigZag, ZigZagBucketGraph, DEFAULT_EXPANSION_DEGREE};

fn merkle_benchmark(c: &mut Criterion) {
    #[cfg(feature = "big-sector-sizes-bench")]
    let params = vec![128, 1024, 1048576];
    #[cfg(not(feature = "big-sector-sizes-bench"))]
    let params = vec![128, 1024];

    c.bench(
        "merkletree",
        ParameterizedBenchmark::new(
            "blake2s",
            move |b, nodes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..32 * *nodes).map(|_| rng.gen()).collect();
                let graph = ZigZagBucketGraph::<Blake2sHasher>::new_zigzag(
                    *nodes,                   // #nodes
                    8,                        // degree
                    DEFAULT_EXPANSION_DEGREE, // expansion degree,
                    new_seed(),
                );

                b.iter(|| black_box(graph.merkle_tree(&data).unwrap()))
            },
            params,
        )
        .with_function("pedersen", move |b, nodes| {
            let mut rng = thread_rng();
            let data: Vec<u8> = (0..32 * *nodes).map(|_| rng.gen()).collect();
            let graph = ZigZagBucketGraph::<PedersenHasher>::new_zigzag(
                *nodes,                   // #nodes
                8,                        // degree
                DEFAULT_EXPANSION_DEGREE, // expansion degree,
                new_seed(),
            );

            b.iter(|| black_box(graph.merkle_tree(&data).unwrap()))
        })
        .sample_size(20),
    );
}

criterion_group!(benches, merkle_benchmark);
criterion_main!(benches);
