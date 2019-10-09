#[macro_use]
extern crate criterion;
#[cfg(feature = "cpu-profile")]
extern crate gperftools;

use criterion::{black_box, Criterion, ParameterizedBenchmark};
use storage_proofs::drgraph::{Graph, BASE_DEGREE};
use storage_proofs::hasher::blake2s::Blake2sHasher;
use storage_proofs::hasher::pedersen::PedersenHasher;
use storage_proofs::hasher::sha256::Sha256Hasher;
use storage_proofs::hasher::Hasher;
use storage_proofs::stacked::{StackedBucketGraph, EXP_DEGREE};

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

fn pregenerate_graph<H: Hasher>(size: usize) -> StackedBucketGraph<H> {
    let seed = [1, 2, 3, 4, 5, 6, 7];
    StackedBucketGraph::<H>::new_stacked(size, BASE_DEGREE, EXP_DEGREE, seed)
}

fn parents_loop<H: Hasher, G: Graph<H>>(graph: &G, parents: &mut [usize]) {
    (0..graph.size())
        .map(|node| graph.parents(node, parents))
        .collect()
}

fn parents_loop_benchmark(cc: &mut Criterion) {
    let sizes = vec![10, 50, 1000];

    cc.bench(
        "parents in a loop",
        ParameterizedBenchmark::new(
            "Blake2s",
            |b, size| {
                let graph = pregenerate_graph::<Blake2sHasher>(*size);
                let mut parents = vec![0; graph.degree()];
                start_profile(&format!("parents-blake2s-{}", *size));
                b.iter(|| black_box(parents_loop::<Blake2sHasher, _>(&graph, &mut parents)));
                stop_profile();
            },
            sizes,
        )
        .with_function("Pedersen", |b, degree| {
            let graph = pregenerate_graph::<PedersenHasher>(*degree);
            let mut parents = vec![0; graph.degree()];
            b.iter(|| black_box(parents_loop::<PedersenHasher, _>(&graph, &mut parents)))
        })
        .with_function("Sha256", |b, degree| {
            let graph = pregenerate_graph::<Sha256Hasher>(*degree);
            let mut parents = vec![0; graph.degree()];
            b.iter(|| black_box(parents_loop::<Sha256Hasher, _>(&graph, &mut parents)))
        }),
    );
}

criterion_group!(benches, parents_loop_benchmark);
criterion_main!(benches);
