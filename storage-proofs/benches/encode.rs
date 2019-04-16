#[macro_use]
extern crate criterion;
#[cfg(feature = "cpu-profile")]
extern crate gperftools;
extern crate storage_proofs;

use criterion::{black_box, Criterion, ParameterizedBenchmark, Throughput};
use pairing::bls12_381::Bls12;
use rand::{thread_rng, Rng};
use storage_proofs::drgraph::{new_seed, Graph};
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::blake2s::Blake2sHasher;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::hasher::sha256::Sha256Hasher;
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::util::{data_at_node_offset, NODE_SIZE};
use storage_proofs::vde;
use storage_proofs::zigzag_graph::{ZigZag, ZigZagBucketGraph};

#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    gperftools::profiler::PROFILER
        .lock()
        .unwrap()
        .start(format!("./{}.profile", stage))
        .unwrap();
}

#[cfg(not(feature = "cpu-profile"))]
#[inline(always)]
fn start_profile(_stage: &str) {}

#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn stop_profile() {
    gperftools::profiler::PROFILER
        .lock()
        .unwrap()
        .stop()
        .unwrap();
}

#[cfg(not(feature = "cpu-profile"))]
#[inline(always)]
fn stop_profile() {}

struct Pregenerated<H: 'static + Hasher> {
    data: Vec<u8>,
    graph: ZigZagBucketGraph<H>,
    replica_id: H::Domain,
}

fn pregenerate_data<H: Hasher>(degree: usize) -> Pregenerated<H> {
    let mut rng = thread_rng();
    let data: Vec<u8> = (0..(degree + 1))
        .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
        .collect();

    let graph = ZigZagBucketGraph::<H>::new_zigzag(degree + 1, degree, 8, new_seed());
    let replica_id: H::Domain = rng.gen();

    Pregenerated {
        data,
        graph,
        replica_id,
    }
}

fn encode_single_node<H: Hasher, G: Graph<H>>(
    data: &mut [u8],
    graph: &G,
    replica_id: &H::Domain,
    node: usize,
    parents: &mut [usize],
) {
    graph.parents(node, parents);
    let key = vde::create_key::<H>(replica_id, node, &parents, data).unwrap();
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;

    let node_data = H::Domain::try_from_bytes(&data[start..end]).unwrap();
    let encoded = H::sloth_encode(&key, &node_data, 0);
    encoded.write_bytes(&mut data[start..end]).unwrap();
}

fn encode_single_node_benchmark(cc: &mut Criterion) {
    let degrees = vec![3, 5];

    cc.bench(
        "encode single node",
        ParameterizedBenchmark::new(
            "Blake2s",
            |b, degree| {
                let Pregenerated {
                    mut data,
                    graph,
                    replica_id,
                } = pregenerate_data::<Blake2sHasher>(*degree);
                let mut parents = vec![0; graph.degree()];
                start_profile(&format!("encode-blake2s-{}", *degree));
                b.iter(|| {
                    black_box(encode_single_node::<Blake2sHasher, _>(
                        &mut data,
                        &graph,
                        &replica_id,
                        *degree,
                        &mut parents,
                    ))
                });
                stop_profile();
            },
            degrees,
        )
        .with_function("Pedersen", |b, degree| {
            let Pregenerated {
                mut data,
                graph,
                replica_id,
            } = pregenerate_data::<PedersenHasher>(*degree);
            let mut parents = vec![0; graph.degree()];
            b.iter(|| {
                black_box(encode_single_node::<PedersenHasher, _>(
                    &mut data,
                    &graph,
                    &replica_id,
                    *degree,
                    &mut parents,
                ))
            })
        })
        .with_function("Sha256", |b, degree| {
            let Pregenerated {
                mut data,
                graph,
                replica_id,
            } = pregenerate_data::<Sha256Hasher>(*degree);
            let mut parents = vec![0; graph.degree()];
            b.iter(|| {
                black_box(encode_single_node::<Sha256Hasher, _>(
                    &mut data,
                    &graph,
                    &replica_id,
                    *degree,
                    &mut parents,
                ))
            })
        })
        .throughput(|_degree| Throughput::Bytes(32)),
    );
}

criterion_group!(benches, encode_single_node_benchmark);
criterion_main!(benches);
