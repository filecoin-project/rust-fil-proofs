use std::sync::Once;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use filecoin_proofs::{
    caches::{get_stacked_srs_key, get_stacked_srs_verifier_key},
    get_seal_inputs, PoRepConfig, PoRepProofPartitions, SectorShape2KiB, SectorShape32GiB,
    SectorSize, POREP_PARTITIONS, SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_GIB,
};
use rand::{thread_rng, Rng};
use storage_proofs_core::{api_version::ApiVersion, is_legacy_porep_id};

static INIT_LOGGER: Once = Once::new();
fn init_logger() {
    INIT_LOGGER.call_once(|| {
        fil_logger::init();
    });
}

fn bench_seal_inputs(c: &mut Criterion) {
    let params = vec![1, 256, 512, 1024];

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
    let comm_r = [5u8; 32];
    let comm_d = [6u8; 32];
    let prover_id = [7u8; 32];

    let ticket = rng.gen();
    let seed = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    let mut group = c.benchmark_group("bench_seal_inputs");
    for iterations in params {
        group
            .bench_function(format!("get-seal-inputs-{}", iterations), |b| {
                b.iter(|| {
                    for _ in 0..iterations {
                        get_seal_inputs::<SectorShape2KiB>(
                            config, comm_r, comm_d, prover_id, sector_id, ticket, seed,
                        )
                        .expect("get seal inputs failed");
                    }
                });
            })
            .sample_size(10)
            .throughput(Throughput::Bytes(iterations as u64))
            .warm_up_time(Duration::from_secs(1));
    }

    group.finish();
}

fn bench_stacked_srs_key(c: &mut Criterion) {
    init_logger();
    let params = vec![128, 256, 512, 1024];

    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));

    let config = PoRepConfig {
        sector_size: SectorSize(SECTOR_SIZE_32_GIB),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS
                .read()
                .expect("POREP_PARTITIONS poisoned")
                .get(&SECTOR_SIZE_32_GIB)
                .expect("unknown sector size"),
        ),
        porep_id,
        api_version: ApiVersion::V1_1_0,
    };

    let mut group = c.benchmark_group("bench-stacked-srs-key");
    for num_proofs_to_aggregate in params {
        group.bench_function(
            format!("get-stacked-srs-key-{}", num_proofs_to_aggregate),
            |b| {
                b.iter(|| {
                    black_box(
                        get_stacked_srs_key::<SectorShape32GiB>(config, num_proofs_to_aggregate)
                            .expect("get stacked srs key failed"),
                    )
                })
            },
        );
    }

    group.finish();
}

fn bench_stacked_srs_verifier_key(c: &mut Criterion) {
    init_logger();
    let params = vec![128, 256, 512, 1024];

    let porep_id_v1_1: u64 = 5; // This is a RegisteredSealProof value

    let mut porep_id = [0u8; 32];
    porep_id[..8].copy_from_slice(&porep_id_v1_1.to_le_bytes());
    assert!(!is_legacy_porep_id(porep_id));

    let config = PoRepConfig {
        sector_size: SectorSize(SECTOR_SIZE_32_GIB),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS
                .read()
                .expect("POREP_PARTITIONS poisoned")
                .get(&SECTOR_SIZE_32_GIB)
                .expect("unknown sector size"),
        ),
        porep_id,
        api_version: ApiVersion::V1_1_0,
    };

    let mut group = c.benchmark_group("bench-stacked-srs-verifier-key");
    for num_proofs_to_aggregate in params {
        group
            .bench_function(
                format!("get-stacked-srs-verifier-key-{}", num_proofs_to_aggregate),
                |b| {
                    b.iter(|| {
                        black_box(
                            get_stacked_srs_verifier_key::<SectorShape32GiB>(
                                config,
                                num_proofs_to_aggregate,
                            )
                            .expect("get stacked srs key failed"),
                        )
                    })
                },
            )
            .sample_size(10)
            .warm_up_time(Duration::from_secs(1));
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_seal_inputs,
    bench_stacked_srs_key,
    bench_stacked_srs_verifier_key,
);
criterion_main!(benches);
