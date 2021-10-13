use std::io::{Cursor, Read};
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use filecoin_proofs::{
    add_piece, get_seal_inputs, PaddedBytesAmount, PoRepConfig, PoRepProofPartitions,
    SectorShape2KiB, SectorSize, UnpaddedBytesAmount, POREP_PARTITIONS, SECTOR_SIZE_2_KIB,
};
use fr32::Fr32Reader;
use rand::{thread_rng, Rng};
use storage_proofs_core::{api_version::ApiVersion, is_legacy_porep_id};

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
    let params = vec![128, 256, 512, 256_000, 512_000, 1_024_000, 2_048_000];

    let mut group = c.benchmark_group("preprocessing");
    for size in params {
        group
            .bench_function(format!("write_padded-{}", size), |b| {
                let data = random_data(size);
                let mut buf = Vec::with_capacity(size);

                start_profile(&format!("write_padded_{}", size));
                b.iter(|| {
                    let mut reader = Fr32Reader::new(Cursor::new(&data));
                    reader.read_to_end(&mut buf).expect("in memory read error");
                    assert!(buf.len() >= data.len());
                    buf.clear();
                });
                stop_profile();
            })
            .sample_size(10)
            .throughput(Throughput::Bytes(size as u64))
            .warm_up_time(Duration::from_secs(1));
    }

    group.finish();
}

fn add_piece_benchmark(c: &mut Criterion) {
    let params = vec![512, 256 * 1024, 512 * 1024, 1024 * 1024, 2 * 1024 * 1024];

    let mut group = c.benchmark_group("preprocessing");
    for size in params {
        group
            .bench_function(format!("add_piece-{}", size), |b| {
                let padded_size = PaddedBytesAmount(size as u64);
                let unpadded_size: UnpaddedBytesAmount = padded_size.into();
                let data = random_data(unpadded_size.0 as usize);
                let mut buf = Vec::with_capacity(size);

                start_profile(&format!("add_piece_{}", size));
                b.iter(|| {
                    add_piece(
                        Cursor::new(&data),
                        &mut buf,
                        unpadded_size,
                        &[unpadded_size][..],
                    )
                    .unwrap();
                    buf.clear();
                });
                stop_profile();
            })
            .sample_size(10)
            .throughput(Throughput::Bytes(size as u64))
            .warm_up_time(Duration::from_secs(1));
    }

    group.finish();
}

fn get_seal_inputs_benchmark(c: &mut Criterion) {
    let params = vec![1, 256, 1024, 2048, 4096, 8192];

    let mut rng = thread_rng();

    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));

    let config = PoRepConfig {
        sector_size: SectorSize(SECTOR_SIZE_2_KIB),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS
                .read()
                .expect("POREP_PARTITIONS poisoned")
                .get(&SECTOR_SIZE_2_KIB)
                .expect("unknown sector size"),
        ),
        porep_id,
        api_version: ApiVersion::V1_1_0,
    };
    let comm_r: [u8; 32] = [5u8; 32];
    let comm_d: [u8; 32] = [6u8; 32];
    let prover_id: [u8; 32] = [7u8; 32];

    let ticket = rng.gen();
    let seed = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    let mut group = c.benchmark_group("get_seal_inputs");
    for iterations in params {
        group
            .bench_function(format!("get_seal_inputs-{}", iterations), |b| {
                start_profile(&format!("get_seal_inputs_{}", iterations));
                b.iter(|| {
                    for _ in 0..iterations {
                        get_seal_inputs::<SectorShape2KiB>(
                            config, comm_r, comm_d, prover_id, sector_id, ticket, seed,
                        )
                        .unwrap();
                    }
                });
                stop_profile();
            })
            .sample_size(10)
            .throughput(Throughput::Bytes(iterations as u64))
            .warm_up_time(Duration::from_secs(1));
    }

    group.finish();
}

criterion_group!(
    benches,
    get_seal_inputs_benchmark,
    preprocessing_benchmark,
    add_piece_benchmark
);
criterion_main!(benches);
