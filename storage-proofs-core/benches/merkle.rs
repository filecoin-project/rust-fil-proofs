use blstrs::Scalar as Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filecoin_hashers::{poseidon::PoseidonHasher, sha256::Sha256Hasher, Domain, Hasher};
use pasta_curves::{Fp, Fq};
use rand::thread_rng;
use storage_proofs_core::merkle::{create_base_merkle_tree, BinaryMerkleTree};

fn bench_with_hasher<H: 'static + Hasher>(c: &mut Criterion, hasher_name: &str) {
    let params = if cfg!(feature = "big-sector-sizes-bench") {
        vec![128, 1024, 1_048_576]
    } else {
        vec![128, 1024]
    };

    let mut group = c.benchmark_group("merkletree-binary");
    for n_nodes in params {
        group.bench_function(format!("nodes={}-{}", n_nodes, hasher_name), |b| {
            let mut rng = thread_rng();
            let data: Vec<u8> = (0..n_nodes)
                .flat_map(|_| H::Domain::random(&mut rng).into_bytes())
                .collect();
            b.iter(|| {
                black_box(
                    create_base_merkle_tree::<BinaryMerkleTree<H>>(None, n_nodes, &data).unwrap(),
                )
            })
        });
    }

    group.finish();
}

fn merkle_benchmark(c: &mut Criterion) {
    bench_with_hasher::<Sha256Hasher<Fr>>(c, "sha256-bls");
    bench_with_hasher::<Sha256Hasher<Fp>>(c, "sha256-pallas");
    bench_with_hasher::<Sha256Hasher<Fq>>(c, "sha256-vesta");

    bench_with_hasher::<PoseidonHasher<Fr>>(c, "poseidon-bls");
    bench_with_hasher::<PoseidonHasher<Fp>>(c, "poseidon-pallas");
    bench_with_hasher::<PoseidonHasher<Fq>>(c, "poseidon-vesta");
}

criterion_group!(benches, merkle_benchmark);
criterion_main!(benches);
