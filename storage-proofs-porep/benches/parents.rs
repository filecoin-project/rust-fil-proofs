use criterion::{black_box, criterion_group, criterion_main, Criterion, ParameterizedBenchmark};
use filecoin_hashers::{blake2s::Blake2sHasher, sha256::Sha256Hasher, Hasher};
#[cfg(feature = "cpu-profile")]
use gperftools::profiler::PROFILER;
use storage_proofs_core::{
    api_version::ApiVersion,
    drgraph::{Graph, BASE_DEGREE},
};
use storage_proofs_porep::stacked::{StackedBucketGraph, EXP_DEGREE};

#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    PROFILER
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
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(feature = "cpu-profile"))]
#[inline(always)]
fn stop_profile() {}

fn pregenerate_graph<H: Hasher>(size: usize, api_version: ApiVersion) -> StackedBucketGraph<H> {
    StackedBucketGraph::<H>::new_stacked(size, BASE_DEGREE, EXP_DEGREE, [32; 32], api_version)
        .unwrap()
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
                let graph = pregenerate_graph::<Blake2sHasher>(*size, ApiVersion::V1_1_0);
                let mut parents = vec![0; graph.degree()];
                start_profile(&format!("parents-blake2s-{}", *size));
                b.iter(|| black_box(parents_loop::<Blake2sHasher, _>(&graph, &mut parents)));
                stop_profile();
            },
            sizes,
        )
        .with_function("Sha256", |b, degree| {
            let graph = pregenerate_graph::<Sha256Hasher>(*degree, ApiVersion::V1_1_0);
            let mut parents = vec![0; graph.degree()];
            b.iter(|| black_box(parents_loop::<Sha256Hasher, _>(&graph, &mut parents)))
        }),
    );
}

criterion_group!(benches, parents_loop_benchmark);
criterion_main!(benches);
