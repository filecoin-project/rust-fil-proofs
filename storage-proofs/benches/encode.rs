use criterion::{
    black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark, Throughput,
};
use ff::Field;
use generic_array::typenum;
use paired::bls12_381::{Bls12, Fr};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use storage_proofs::drgraph::new_seed;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::sha256::Sha256Hasher;
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::porep::stacked::{create_key, create_key_exp, StackedBucketGraph};

struct Pregenerated<H: 'static + Hasher> {
    data: Vec<u8>,
    replica_id: H::Domain,
    graph: StackedBucketGraph<H, typenum::U14>,
}

fn pregenerate_data<H: Hasher>(degree: usize) -> Pregenerated<H> {
    assert_eq!(degree, 6 + 8);
    let mut rng = thread_rng();
    let size = degree * 4 * 1024 * 1024;
    let data: Vec<u8> = (0..size)
        .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(&mut rng)))
        .collect();
    let replica_id: H::Domain = H::Domain::random(&mut rng);

    let graph = StackedBucketGraph::<H, typenum::U14>::new_stacked(size, 6, 8, new_seed()).unwrap();

    Pregenerated {
        data,
        replica_id,
        graph,
    }
}

fn kdf_benchmark(c: &mut Criterion) {
    let degrees = vec![14];

    c.bench(
        "kdf",
        ParameterizedBenchmark::new(
            "exp",
            |b, degree| {
                let Pregenerated {
                    mut data,
                    replica_id,
                    graph,
                } = pregenerate_data::<Sha256Hasher>(*degree);

                let exp_data = data.clone();
                b.iter(|| {
                    let mut hasher = Sha256::new();
                    hasher.input(AsRef::<[u8]>::as_ref(&replica_id));
                    hasher.input(&(1u64).to_be_bytes()[..]);

                    black_box(create_key_exp(&graph, hasher, &exp_data, &mut data, 1))
                })
            },
            degrees,
        )
        .with_function("non-exp", move |b, degree| {
            let Pregenerated {
                mut data,
                replica_id,
                graph,
            } = pregenerate_data::<Sha256Hasher>(*degree);
            b.iter(|| {
                let mut hasher = Sha256::new();
                hasher.input(AsRef::<[u8]>::as_ref(&replica_id));

                black_box(create_key(&graph, hasher, &mut data, 1))
            })
        })
        .sample_size(20)
        .throughput(|_s| {
            Throughput::Bytes(
                /* replica id + 37 parents + node id + */ 32 + 37 * 32 + 1 * 8,
            )
        }),
    );
}

criterion_group!(benches, kdf_benchmark);
criterion_main!(benches);
