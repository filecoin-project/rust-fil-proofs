use bellperson::bls::Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ff::Field;
use rand::thread_rng;
use storage_proofs_core::fr32::fr_into_bytes;
use storage_proofs_core::hasher::sha256::Sha256Hasher;
use storage_proofs_core::hasher::{Domain, Hasher};
use storage_proofs_porep::stacked::{
    create_label::single::{create_label, create_label_exp},
    StackedBucketGraph,
};

struct Pregenerated<H: 'static + Hasher> {
    data: Vec<u8>,
    replica_id: H::Domain,
    graph: StackedBucketGraph<H>,
}

fn pregenerate_data<H: Hasher>(degree: usize) -> Pregenerated<H> {
    assert_eq!(degree, 6 + 8);
    let mut rng = thread_rng();
    let size = degree * 4 * 1024 * 1024;
    let data: Vec<u8> = (0..size)
        .flat_map(|_| fr_into_bytes(&Fr::random(&mut rng)))
        .collect();
    let replica_id: H::Domain = H::Domain::random(&mut rng);

    let graph = StackedBucketGraph::<H>::new_stacked(size, 6, 8, [32; 32]).unwrap();

    Pregenerated {
        data,
        replica_id,
        graph,
    }
}

fn kdf_benchmark(c: &mut Criterion) {
    let degree = 14;
    let Pregenerated {
        data,
        replica_id,
        graph,
    } = pregenerate_data::<Sha256Hasher>(degree);

    let mut group = c.benchmark_group("kdf");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(
        /* replica id + 37 parents + node id */ 39 * 32,
    ));

    group.bench_function("exp", |b| {
        let mut raw_data = data.clone();
        raw_data.extend_from_slice(&data);
        let (data, exp_data) = raw_data.split_at_mut(data.len());

        let graph = &graph;

        b.iter(|| {
            black_box(create_label_exp(
                graph,
                None,
                &replica_id,
                &*exp_data,
                data,
                1,
                2,
            ))
        })
    });

    group.bench_function("non-exp", |b| {
        let mut data = data.clone();
        let graph = &graph;

        b.iter(|| black_box(create_label(graph, None, &replica_id, &mut data, 1, 2)))
    });

    group.finish();
}

criterion_group!(benches, kdf_benchmark);
criterion_main!(benches);
