#[macro_use]
extern crate criterion;

use criterion::{Criterion, ParameterizedBenchmark};
use rand::{thread_rng, Rng};

use storage_proofs::crypto::parallel_pedersen::ParallelPedersen;

fn parallel_pedersen_benchmark(c: &mut Criterion) {
    let preimage_lens = vec![32, 64, 96];

    c.bench(
        "parallel-pedersen-hash",
        ParameterizedBenchmark::new(
            "1-thread-1-preimage-no-disk-reads",
            move |b, preimage_len| {
                let mut rng = thread_rng();
                let preimage: Vec<u8> = (0..*preimage_len).map(|_| rng.gen()).collect();
                let preimage_id = 0usize;

                b.iter(|| {
                    let mut pedersen_coordinator = ParallelPedersen::new();
                    let mut hasher = pedersen_coordinator.new_worker();
                    hasher.new_preimage(preimage_id);
                    hasher.update_preimage(preimage_id, &preimage);
                    hasher.finalize_preimage(preimage_id)
                })
            },
            preimage_lens,
        ),
    );
}

criterion_group!(benches, parallel_pedersen_benchmark);
criterion_main!(benches);
