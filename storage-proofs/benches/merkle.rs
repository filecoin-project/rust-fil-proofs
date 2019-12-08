use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use rand::{thread_rng, Rng};
use storage_proofs::drgraph::{new_seed, Graph, BASE_DEGREE};
use storage_proofs::hasher::blake2s::Blake2sHasher;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::stacked::{StackedBucketGraph, EXP_DEGREE};

fn merkle_benchmark(c: &mut Criterion) {
    #[cfg(feature = "big-sector-sizes-bench")]
    let params = vec![128, 1024, 1048576];
    #[cfg(not(feature = "big-sector-sizes-bench"))]
    let params = vec![128, 1024];

    c.bench(
        "merkletree",
        ParameterizedBenchmark::new(
            "blake2s",
            move |b, n_nodes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..32 * *n_nodes).map(|_| rng.gen()).collect();
                let graph = StackedBucketGraph::<Blake2sHasher>::new_stacked(
                    *n_nodes,
                    BASE_DEGREE,
                    EXP_DEGREE,
                    new_seed(),
                )
                .unwrap();

                b.iter(|| black_box(graph.merkle_tree(&data).unwrap()))
            },
            params,
        )
        .with_function("pedersen", move |b, n_nodes| {
            let mut rng = thread_rng();
            let data: Vec<u8> = (0..32 * *n_nodes).map(|_| rng.gen()).collect();
            let graph = StackedBucketGraph::<PedersenHasher>::new_stacked(
                *n_nodes,
                BASE_DEGREE,
                EXP_DEGREE,
                new_seed(),
            )
            .unwrap();

            b.iter(|| black_box(graph.merkle_tree(&data).unwrap()))
        })
        .sample_size(20),
    );
}

criterion_group!(benches, merkle_benchmark);
criterion_main!(benches);
