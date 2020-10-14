use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use rand::{thread_rng, Rng};
use storage_proofs_core::hasher::{PoseidonHasher, Sha256Hasher};
use storage_proofs_core::merkle::{create_base_merkle_tree, BinaryMerkleTree};

fn merkle_benchmark(c: &mut Criterion) {
    #[cfg(feature = "big-sector-sizes-bench")]
    let params = vec![128, 1024, 1_048_576];
    #[cfg(not(feature = "big-sector-sizes-bench"))]
    let params = vec![128, 1024];

    c.bench(
        "merkletree-binary",
        ParameterizedBenchmark::new(
            "sha256",
            move |b, n_nodes| {
                let mut rng = thread_rng();
                let data: Vec<u8> = (0..32 * *n_nodes).map(|_| rng.gen()).collect();
                b.iter(|| {
                    black_box(
                        create_base_merkle_tree::<BinaryMerkleTree<Sha256Hasher>>(
                            None, *n_nodes, &data,
                        )
                        .unwrap(),
                    )
                })
            },
            params,
        )
        .with_function("poseidon", move |b, n_nodes| {
            let mut rng = thread_rng();
            let data: Vec<u8> = (0..32 * *n_nodes).map(|_| rng.gen()).collect();

            b.iter(|| {
                black_box(
                    create_base_merkle_tree::<BinaryMerkleTree<PoseidonHasher>>(
                        None, *n_nodes, &data,
                    )
                    .unwrap(),
                )
            })
        })
        .sample_size(20),
    );
}

criterion_group!(benches, merkle_benchmark);
criterion_main!(benches);
