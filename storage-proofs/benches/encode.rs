use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use ff::Field;
use paired::bls12_381::{Bls12, Fr};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use storage_proofs::drgraph::new_seed;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::sha256::Sha256Hasher;
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::stacked::{create_key, StackedBucketGraph};

struct Pregenerated<H: 'static + Hasher> {
    data: Vec<u8>,
    parents: Vec<u32>,
    replica_id: H::Domain,
    graph: StackedBucketGraph<H>,
}

fn pregenerate_data<H: Hasher>(degree: usize) -> Pregenerated<H> {
    let mut rng = thread_rng();
    let data: Vec<u8> = (0..(degree + 1))
        .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(&mut rng)))
        .collect();
    let parents: Vec<u32> = (0..degree as u32).map(|pos| pos).collect();
    let replica_id: H::Domain = H::Domain::random(&mut rng);

    let graph = StackedBucketGraph::<H>::new_stacked(degree + 1, degree, 0, new_seed()).unwrap();

    Pregenerated {
        data,
        parents,
        replica_id,
        graph,
    }
}

fn kdf_benchmark(c: &mut Criterion) {
    let degrees = vec![3, 5, 10, 14, 20];

    c.bench(
        "kdf",
        ParameterizedBenchmark::new(
            "sha256",
            |b, degree| {
                let Pregenerated {
                    data,
                    parents,
                    replica_id,
                    graph,
                } = pregenerate_data::<Sha256Hasher>(*degree);

                b.iter(|| {
                    let mut hasher = Sha256::new();
                    hasher.input(AsRef::<[u8]>::as_ref(&replica_id));
                    hasher.input(&(1u64).to_be_bytes()[..]);

                    black_box(create_key(&graph, hasher, &parents, None, &data, 1, 1))
                })
            },
            degrees,
        ),
    );
}

criterion_group!(benches, kdf_benchmark);
criterion_main!(benches);
