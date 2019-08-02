#[macro_use]
extern crate criterion;

use criterion::{black_box, Criterion, ParameterizedBenchmark};
use rand::{thread_rng, Rng};
use storage_proofs::drgraph::{new_seed, Graph};
use storage_proofs::hasher::blake2s::Blake2sHasher;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::util::NODE_SIZE;
use storage_proofs::zigzag_graph::{ZigZag, ZigZagBucketGraph, DEFAULT_EXPANSION_DEGREE};

const BASE_DEGREE: usize = 8;

fn hybrid_merkle_benchmark(c: &mut Criterion) {
    #[cfg(feature = "big-sector-sizes-bench")]
    let params = vec![128, 1024, 1048576];
    #[cfg(not(feature = "big-sector-sizes-bench"))]
    let params = vec![128, 1024];

    c.bench(
        "hybrid_merkle",
        ParameterizedBenchmark::new(
            "blake2s_no_beta",
            move |b, n_nodes| {
                let mut rng = thread_rng();
                let n_bytes = NODE_SIZE * n_nodes;
                let data: Vec<u8> = (0..n_bytes).map(|_| rng.gen()).collect();
                let graph = ZigZagBucketGraph::<Blake2sHasher, Blake2sHasher>::new_zigzag(
                    *n_nodes,
                    BASE_DEGREE,
                    DEFAULT_EXPANSION_DEGREE,
                    new_seed(),
                );

                // Set beta height to zero.
                b.iter(|| black_box(graph.hybrid_merkle_tree(&data, 0).unwrap()))
            },
            params,
        )
        .with_function("pedersen_no_beta", move |b, n_nodes| {
            let mut rng = thread_rng();
            let n_bytes = NODE_SIZE * n_nodes;
            let data: Vec<u8> = (0..n_bytes).map(|_| rng.gen()).collect();
            let graph = ZigZagBucketGraph::<PedersenHasher, PedersenHasher>::new_zigzag(
                *n_nodes,
                BASE_DEGREE,
                DEFAULT_EXPANSION_DEGREE,
                new_seed(),
            );

            // Set beta height to zero.
            b.iter(|| black_box(graph.hybrid_merkle_tree(&data, 0).unwrap()))
        })
        .with_function("pedersen_blake2s_no_beta", move |b, n_nodes| {
            let mut rng = thread_rng();
            let n_bytes = NODE_SIZE * n_nodes;
            let data: Vec<u8> = (0..n_bytes).map(|_| rng.gen()).collect();
            let graph = ZigZagBucketGraph::<PedersenHasher, Blake2sHasher>::new_zigzag(
                *n_nodes,
                BASE_DEGREE,
                DEFAULT_EXPANSION_DEGREE,
                new_seed(),
            );

            // Set beta height to zero.
            b.iter(|| black_box(graph.hybrid_merkle_tree(&data, 0).unwrap()))
        })
        .with_function("pedersen_blake2s_beta_height_1", move |b, n_nodes| {
            let mut rng = thread_rng();
            let n_bytes = NODE_SIZE * n_nodes;
            let data: Vec<u8> = (0..n_bytes).map(|_| rng.gen()).collect();
            let graph = ZigZagBucketGraph::<PedersenHasher, Blake2sHasher>::new_zigzag(
                *n_nodes,
                BASE_DEGREE,
                DEFAULT_EXPANSION_DEGREE,
                new_seed(),
            );

            // Set beta height to zero.
            b.iter(|| black_box(graph.hybrid_merkle_tree(&data, 1).unwrap()))
        })
        .sample_size(20),
    );
}

criterion_group!(benches, hybrid_merkle_benchmark);
criterion_main!(benches);
