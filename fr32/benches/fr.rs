use blstrs::Scalar as Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::Field;
use fr32::{bytes_into_fr, fr_into_bytes};
use rand::thread_rng;

fn fr_benchmark(c: &mut Criterion) {
    c.bench_function("fr-to-bytes-32", move |b| {
        let mut rng = thread_rng();
        let fr = Fr::random(&mut rng);

        b.iter(|| black_box(fr_into_bytes(&fr)))
    });

    c.bench_function("bytes-32-to-fr", move |b| {
        let mut rng = thread_rng();
        let fr = Fr::random(&mut rng);
        let bytes = fr_into_bytes(&fr);

        b.iter(|| black_box(bytes_into_fr(&bytes).unwrap()))
    });
}

criterion_group!(benches, fr_benchmark);
criterion_main!(benches);
