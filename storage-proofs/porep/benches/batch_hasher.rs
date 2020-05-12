use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use paired::bls12_381::Fr;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use sha2raw::Sha256;
use storage_proofs_core::fr32::fr_into_bytes;
use storage_proofs_porep::nse::*;

fn bench_batch_hash(c: &mut Criterion) {
    let rng = &mut XorShiftRng::seed_from_u64(5);

    let window_size = 1024 * 1024 * 1024 * 4;
    let config = Config {
        k: 8,
        num_nodes_window: window_size / 32,
        degree_expander: 384,
        degree_butterfly: 4,
        num_expander_layers: 6,
        num_butterfly_layers: 4,
        sector_size: 1 * window_size,
    };
    let k = config.k;
    let degree = config.degree_expander;

    let data: Vec<u8> = (0..config.num_nodes_window)
        .map(|_| fr_into_bytes(&Fr::random(rng)))
        .flatten()
        .collect();
    let graph: ExpanderGraph = config.into();
    let parents: Vec<_> = graph.expanded_parents(4).flatten().collect();

    c.bench_function("batch-hash", move |b| {
        b.iter(|| {
            let hasher = Sha256::new();
            let res = batch_hash(k as usize, degree, hasher, &parents, &data);
            black_box(res);
        });
    });
}

criterion_group!(benches, bench_batch_hash);
criterion_main!(benches);
