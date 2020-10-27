use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use storage_proofs_core::{
    drgraph::{Graph, BASE_DEGREE},
    hasher::blake2s::Blake2sHasher,
    hasher::sha256::Sha256Hasher,
    hasher::Hasher,
};
use storage_proofs_porep::stacked::{StackedBucketGraph, EXP_DEGREE};

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
    StackedBucketGraph::<H>::new_stacked(size, BASE_DEGREE, EXP_DEGREE, [32; 32]).unwrap()
}

fn parents_loop<H: Hasher, G: Graph<H>>(graph: &G, parents: &mut [u32]) {
    (0..graph.size())
        .map(|node| graph.parents(node, parents).unwrap())
        .collect()
}

#[allow(clippy::unit_arg)]
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
        .with_function("Sha256", |b, degree| {
            let graph = pregenerate_graph::<Sha256Hasher>(*degree);
            let mut parents = vec![0; graph.degree()];
            b.iter(|| black_box(parents_loop::<Sha256Hasher, _>(&graph, &mut parents)))
        }),
    );
}

criterion_group!(benches, parents_loop_benchmark);
criterion_main!(benches);
