use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use paired::bls12_381::{Bls12, Fr};
use rand::thread_rng;
use storage_proofs::fr32::{bytes_into_fr, fr_into_bytes};

fn fr_benchmark(c: &mut Criterion) {
    c.bench_function("fr-to-bytes-32", move |b| {
        let mut rng = thread_rng();
        let fr = Fr::random(&mut rng);

        b.iter(|| black_box(fr_into_bytes::<Bls12>(&fr)))
    });

    c.bench_function("bytes-32-to-fr", move |b| {
        let mut rng = thread_rng();
        let fr = Fr::random(&mut rng);
        let bytes = fr_into_bytes::<Bls12>(&fr);

        b.iter(|| black_box(bytes_into_fr::<Bls12>(&bytes).unwrap()))
    });
}

criterion_group!(benches, fr_benchmark);
criterion_main!(benches);
