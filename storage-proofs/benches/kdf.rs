#[macro_use]
extern crate criterion;
extern crate bitvec;
extern crate rand;
extern crate storage_proofs;

use criterion::{Criterion, ParameterizedBenchmark};
use rand::{thread_rng, Rng};

use storage_proofs::hasher::{Blake2sHasher, Hasher, PedersenHasher, Sha256Hasher};

fn kdf_benchmark(c: &mut Criterion) {
    let m = 6;
    let params = vec![(m + 1) * 32];

    c.bench(
        "kdf",
        ParameterizedBenchmark::new(
            "blake2s",
            |b, bytes| {
                let mut rng = thread_rng();
                let ciphertexts: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();
                let m = 6;

                b.iter(|| Blake2sHasher::kdf(&ciphertexts, m))
            },
            params,
        )
        .with_function("sha256", move |b, bytes| {
            let mut rng = thread_rng();
            let ciphertexts: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();
            let m = 6;

            b.iter(|| Sha256Hasher::kdf(&ciphertexts, m))
        })
        .with_function("pedersen", move |b, bytes| {
            let mut rng = thread_rng();
            let ciphertexts: Vec<u8> = (0..*bytes).map(|_| rng.gen()).collect();
            let m = 6;

            b.iter(|| PedersenHasher::kdf(&ciphertexts, m))
        })
        .sample_size(20),
    );
}

criterion_group!(benches, kdf_benchmark);
criterion_main!(benches);
