use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use ff::Field;
use paired::bls12_381::{Bls12, Fr};
use rand::thread_rng;
use storage_proofs::drgraph::{new_seed, Graph};
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::blake2s::Blake2sHasher;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::hasher::sha256::Sha256Hasher;
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::stacked::StackedBucketGraph;
use storage_proofs::util::{data_at_node_offset, NODE_SIZE};

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

fn encode_single_node<H: Hasher>(
    data: &mut [u8],
    parents: &[u32],
    replica_id: &H::Domain,
    node: usize,
    graph: &StackedBucketGraph<H>,
) {
    let key = graph
        .create_key(replica_id, node, parents, data, None)
        .unwrap();
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;

    let node_data = H::Domain::try_from_bytes(&data[start..end]).unwrap();
    let key_data = H::Domain::try_from_bytes(&key).unwrap();
    let encoded = H::sloth_encode(&key_data, &node_data).unwrap();
    encoded.write_bytes(&mut data[start..end]).unwrap();
}

fn kdf_benchmark(c: &mut Criterion) {
    let degrees = vec![3, 5, 10];

    c.bench(
        "kdf",
        ParameterizedBenchmark::new(
            "blake2s",
            |b, degree| {
                let Pregenerated {
                    mut data,
                    parents,
                    replica_id,
                    graph,
                } = pregenerate_data::<Blake2sHasher>(*degree);
                b.iter(|| {
                    black_box(graph.create_key(&replica_id, *degree, &parents, &mut data, None))
                })
            },
            degrees,
        )
        .with_function("pedersen", |b, degree| {
            let Pregenerated {
                mut data,
                parents,
                replica_id,
                graph,
            } = pregenerate_data::<PedersenHasher>(*degree);
            b.iter(|| black_box(graph.create_key(&replica_id, *degree, &parents, &mut data, None)))
        }),
    );
}

fn encode_single_node_benchmark(c: &mut Criterion) {
    let degrees = vec![3, 5, 10];

    c.bench(
        "encode-node",
        ParameterizedBenchmark::new(
            "blake2s",
            |b, degree| {
                let Pregenerated {
                    mut data,
                    parents,
                    replica_id,
                    graph,
                } = pregenerate_data::<Blake2sHasher>(*degree);
                b.iter(|| {
                    black_box(encode_single_node::<Blake2sHasher>(
                        &mut data,
                        &parents,
                        &replica_id,
                        *degree,
                        &graph,
                    ))
                })
            },
            degrees,
        )
        .with_function("pedersen", |b, degree| {
            let Pregenerated {
                mut data,
                parents,
                replica_id,
                graph,
            } = pregenerate_data::<PedersenHasher>(*degree);
            b.iter(|| {
                black_box(encode_single_node::<PedersenHasher>(
                    &mut data,
                    &parents,
                    &replica_id,
                    *degree,
                    &graph,
                ))
            })
        })
        .with_function("sha256", |b, degree| {
            let Pregenerated {
                mut data,
                parents,
                replica_id,
                graph,
            } = pregenerate_data::<Sha256Hasher>(*degree);
            b.iter(|| {
                black_box(encode_single_node::<Sha256Hasher>(
                    &mut data,
                    &parents,
                    &replica_id,
                    *degree,
                    &graph,
                ))
            })
        }),
    );
}

criterion_group!(benches, encode_single_node_benchmark, kdf_benchmark);
criterion_main!(benches);
