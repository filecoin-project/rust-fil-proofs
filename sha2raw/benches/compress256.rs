use criterion::{criterion_group, criterion_main, Criterion, ParameterizedBenchmark, Throughput};
use rand::{thread_rng, Rng};
use rand::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use sha2raw::Sha256;
use std::io::{self, Read};
use std::time::Duration;
use sha2raw::sha256_intrinsics;

fn compress256(sha: &mut Sha256) {
    let rng = &mut XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let mut input = vec![0u8; 64];
    rng.fill_bytes(&mut input);
    let chunked = input.chunks(32).collect::<Vec<_>>();

    //sha.len += (chunked.len() as u64) << 8;
    unsafe { sha256_intrinsics::compress256(&mut sha.state, &chunked) };
}

fn compress256_benchmark(c: &mut Criterion) {
    c.bench(
        "compress256_benchmark",
        ParameterizedBenchmark::new(
            "compress256_benchmark",
            |b, size| {
                let mut sha = Sha256::new();
                b.iter(|| compress256(&mut sha))
            },
            vec![128, 256, 1_024_000],
            //vec![128, 256, 512, 256_000, 512_000, 1_024_000, 2_048_000],
        )
            .sample_size(10)
            .throughput(|s| Throughput::Bytes(*s as u64))
            .warm_up_time(Duration::from_secs(1)),
    );
}

criterion_group!(benches, compress256_benchmark);
criterion_main!(benches);
