use anyhow::Result;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filecoin_hashers::{
    poseidon::PoseidonDomain, poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain,
};
use rand::{thread_rng, Rng};
use storage_proofs_core::merkle::{create_base_merkle_tree, BinaryMerkleTree};

fn merkle_benchmark_sha256(c: &mut Criterion) {
    let params = if cfg!(feature = "big-sector-sizes-bench") {
        vec![128, 1024, 1_048_576]
    } else {
        vec![128, 1024]
    };

    let mut group = c.benchmark_group("merkletree-binary");
    for n_nodes in params {
        group.bench_function(format!("sha256-{}", n_nodes), |b| {
            let mut rng = thread_rng();
            let data: Vec<u8> = (0..32 * n_nodes).map(|_| rng.gen()).collect();
            b.iter(|| {
                black_box(
                    create_base_merkle_tree::<BinaryMerkleTree<Sha256Hasher>>(None, n_nodes, &data)
                        .unwrap(),
                )
            })
        });
    }

    group.finish();
}

fn merkle_benchmark_poseidon(c: &mut Criterion) {
    let params = if cfg!(feature = "big-sector-sizes-bench") {
        vec![64, 128, 1024, 1_048_576]
    } else {
        vec![64, 128, 1024]
    };

    let mut group = c.benchmark_group("merkletree-binary");
    for n_nodes in params {
        group.bench_function(format!("poseidon-{}", n_nodes), |b| {
            let mut rng = thread_rng();
            let mut data: Vec<u8> = Vec::with_capacity(32 * n_nodes);
            (0..n_nodes)
                .into_iter()
                .try_for_each(|_| -> Result<()> {
                    let node = PoseidonDomain::random(&mut rng);
                    data.extend(node.into_bytes());
                    Ok(())
                })
                .expect("failed to generate data");

            b.iter(|| {
                black_box(
                    create_base_merkle_tree::<BinaryMerkleTree<PoseidonHasher>>(
                        None, n_nodes, &data,
                    )
                    .unwrap(),
                )
            })
        });
    }

    group.finish();
}

criterion_group!(benches, merkle_benchmark_sha256, merkle_benchmark_poseidon);
criterion_main!(benches);
