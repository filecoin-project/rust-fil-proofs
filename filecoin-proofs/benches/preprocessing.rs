use std::io::{self, Read};
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, ParameterizedBenchmark, Throughput};
use filecoin_proofs::{add_piece, fr32_reader::Fr32Reader, PaddedBytesAmount, UnpaddedBytesAmount};
use rand::{thread_rng, Rng};

#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    gperftools::profiler::PROFILER
        .lock()
        .expect("PROFILER poisoned")
        .start(format!("./{}.profile", stage))
        .expect("failed to start profiler");
}

#[cfg(not(feature = "cpu-profile"))]
#[inline(always)]
fn start_profile(_stage: &str) {}

#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn stop_profile() {
    gperftools::profiler::PROFILER
        .lock()
        .expect("PROFILER poisoned")
        .stop()
        .expect("failed to start profiler");
}

#[cfg(not(feature = "cpu-profile"))]
#[inline(always)]
fn stop_profile() {}

fn random_data(size: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

fn preprocessing_benchmark(c: &mut Criterion) {
    c.bench(
        "preprocessing",
        ParameterizedBenchmark::new(
            "write_padded",
            |b, size| {
                let data = random_data(*size);
                let mut buf = Vec::with_capacity(*size);

                start_profile(&format!("write_padded_{}", *size));
                b.iter(|| {
                    let mut reader = Fr32Reader::new(io::Cursor::new(&data));
                    reader.read_to_end(&mut buf).expect("in memory read error");
                    assert!(buf.len() >= data.len());
                    buf.clear();
                });
                stop_profile();
            },
            vec![128, 256, 512, 256_000, 512_000, 1_024_000, 2_048_000],
        )
        .sample_size(10)
        .throughput(|s| Throughput::Bytes(*s as u64))
        .warm_up_time(Duration::from_secs(1)),
    );
}

fn add_piece_benchmark(c: &mut Criterion) {
    c.bench(
        "preprocessing",
        ParameterizedBenchmark::new(
            "add_piece",
            |b, size| {
                let padded_size = PaddedBytesAmount(*size as u64);
                let unpadded_size: UnpaddedBytesAmount = padded_size.into();
                let data = random_data(unpadded_size.0 as usize);
                let mut buf = Vec::with_capacity(*size);

                start_profile(&format!("add_piece_{}", *size));
                b.iter(|| {
                    add_piece(
                        io::Cursor::new(&data),
                        &mut buf,
                        unpadded_size,
                        &[unpadded_size][..],
                    )
                    .unwrap();
                    buf.clear();
                });
                stop_profile();
            },
            vec![512, 256 * 1024, 512 * 1024, 1024 * 1024, 2 * 1024 * 1024],
        )
        .sample_size(10)
        .throughput(|s| Throughput::Bytes(*s as u64))
        .warm_up_time(Duration::from_secs(1)),
    );
}

criterion_group!(benches, preprocessing_benchmark, add_piece_benchmark);
criterion_main!(benches);
