use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use generic_array::typenum::{U0, U2, U8};
use halo2_proofs::pasta::Fp;
use storage_proofs_core::{
    halo2::{self, CircuitRows},
    merkle::MerkleTreeWrapper,
};
use storage_proofs_porep::stacked::{
    halo2::{
        constants::{
            SECTOR_NODES_16_KIB, SECTOR_NODES_16_MIB, SECTOR_NODES_2_KIB, SECTOR_NODES_32_GIB,
            SECTOR_NODES_4_KIB, SECTOR_NODES_512_MIB, SECTOR_NODES_64_GIB, SECTOR_NODES_8_MIB,
        },
        SdrPorepCircuit,
    },
    StackedDrg,
};

use filecoin_proofs::{
    constants::{DefaultPieceHasher, DefaultTreeHasher},
    MockStore,
};

#[allow(clippy::unit_arg)]
fn bench_halo2_keypair_base(c: &mut Criterion) {
    let leaf_counts = vec![SECTOR_NODES_2_KIB, SECTOR_NODES_512_MIB];
    for leaf_count in leaf_counts {
        let sector_bytes = 32 * leaf_count;
        let benchmark_prefix = format!(
            "merkle-poseidon-arity={}-{}-{}/leaves={}/sector_size={}",
            8, 0, 0, leaf_count, sector_bytes
        );

        match leaf_count {
            SECTOR_NODES_2_KIB => {
                let start = Instant::now();
                let circ = SdrPorepCircuit::<Fp, U8, U0, U0, SECTOR_NODES_2_KIB>::blank_circuit();
                println!("\n{}-keypair-base-BlankCircuit/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let start = Instant::now();
                let _keypair = <StackedDrg<
                    '_,
                    MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U0, U0>,
                    DefaultPieceHasher<Fp>,
                > as halo2::CompoundProof<Fp, SECTOR_NODES_2_KIB>>::create_keypair(
                    &circ
                )
                .expect("failed to create halo2 keypair");
                println!("\n{}-keypair-base-FirstTime/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let mut keypair_benchmarks =
                    c.benchmark_group(format!("{}-keypair-base", benchmark_prefix));
                keypair_benchmarks.sample_size(10);
                let start = Instant::now();
                keypair_benchmarks.bench_function("Halo2Keypair::create", |b| {
                    b.iter(|| {
                        black_box({
                            <StackedDrg<
                                '_,
                                MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U0, U0>,
                                DefaultPieceHasher<Fp>,
                            > as halo2::CompoundProof<Fp, SECTOR_NODES_2_KIB>>::create_keypair(
                                &circ,
                            )
                            .expect("failed to create halo2 keypair");
                        });
                    })
                });
                keypair_benchmarks.finish();

                println!("\n{}-keypair-base/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
            }
            SECTOR_NODES_8_MIB => {
                let start = Instant::now();
                let circ = SdrPorepCircuit::<Fp, U8, U0, U0, SECTOR_NODES_8_MIB>::blank_circuit();
                println!("\n{}-keypair-base-BlankCircuit/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let start = Instant::now();
                let _keypair = <StackedDrg<
                    '_,
                    MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U0, U0>,
                    DefaultPieceHasher<Fp>,
                > as halo2::CompoundProof<Fp, SECTOR_NODES_8_MIB>>::create_keypair(
                    &circ
                )
                .expect("failed to create halo2 keypair");
                println!("\n{}-keypair-base-FirstTime/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let mut keypair_benchmarks =
                    c.benchmark_group(format!("{}-keypair-base", benchmark_prefix));
                keypair_benchmarks.sample_size(10);
                let start = Instant::now();
                keypair_benchmarks.bench_function("Halo2Keypair::create", |b| {
                    b.iter(|| {
                        black_box({
                            <StackedDrg<
                                '_,
                                MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U0, U0>,
                                DefaultPieceHasher<Fp>,
                            > as halo2::CompoundProof<Fp, SECTOR_NODES_8_MIB>>::create_keypair(
                                &circ,
                            )
                            .expect("failed to create halo2 keypair");
                        });
                    })
                });
                keypair_benchmarks.finish();

                println!("\n{}-keypair-base/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
            }
            SECTOR_NODES_512_MIB => {
                let start = Instant::now();
                let circ = SdrPorepCircuit::<Fp, U8, U0, U0, SECTOR_NODES_512_MIB>::blank_circuit();
                println!("\n{}-keypair-base-BlankCircuit/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let start = Instant::now();
                let _keypair = <StackedDrg<
                    '_,
                    MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U0, U0>,
                    DefaultPieceHasher<Fp>,
                > as halo2::CompoundProof<Fp, SECTOR_NODES_512_MIB>>::create_keypair(
                    &circ
                )
                .expect("failed to create halo2 keypair");
                println!("\n{}-keypair-base-FirstTime/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let mut keypair_benchmarks =
                    c.benchmark_group(format!("{}-keypair-base", benchmark_prefix));
                keypair_benchmarks.sample_size(10);
                let start = Instant::now();
                keypair_benchmarks.bench_function("Halo2Keypair::create", |b| {
                    b.iter(|| {
                        black_box({
                            <StackedDrg<
                                '_,
                                MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U0, U0>,
                                DefaultPieceHasher<Fp>,
                            > as halo2::CompoundProof<Fp, SECTOR_NODES_512_MIB>>::create_keypair(
                                &circ,
                            )
                            .expect("failed to create halo2 keypair");
                        });
                    })
                });
                keypair_benchmarks.finish();

                println!("\n{}-keypair-base/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
            }
            _ => panic!("Unsupported leaf_count"),
        };
    }
}

#[allow(clippy::unit_arg)]
fn bench_halo2_keypair_sub_2(c: &mut Criterion) {
    let leaf_counts = vec![SECTOR_NODES_4_KIB, SECTOR_NODES_16_MIB];
    for leaf_count in leaf_counts {
        let sector_bytes = 32 * leaf_count;
        let benchmark_prefix = format!(
            "merkle-poseidon-arity={}-{}-{}/leaves={}/sector_size={}",
            8, 2, 0, leaf_count, sector_bytes
        );

        match leaf_count {
            SECTOR_NODES_4_KIB => {
                let start = Instant::now();
                let circ = SdrPorepCircuit::<Fp, U8, U2, U0, SECTOR_NODES_4_KIB>::blank_circuit();
                println!("\n{}-keypair-base-BlankCircuit/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let start = Instant::now();
                let _keypair = <StackedDrg<
                    '_,
                    MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U2, U0>,
                    DefaultPieceHasher<Fp>,
                > as halo2::CompoundProof<Fp, SECTOR_NODES_4_KIB>>::create_keypair(
                    &circ
                )
                .expect("failed to create halo2 keypair");
                println!("\n{}-keypair-base-FirstTime/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let mut keypair_benchmarks =
                    c.benchmark_group(format!("{}-keypair-base", benchmark_prefix));
                keypair_benchmarks.sample_size(10);
                let start = Instant::now();
                keypair_benchmarks.bench_function("Halo2Keypair::create", |b| {
                    b.iter(|| {
                        black_box({
                            <StackedDrg<
                                '_,
                                MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U2, U0>,
                                DefaultPieceHasher<Fp>,
                            > as halo2::CompoundProof<Fp, SECTOR_NODES_4_KIB>>::create_keypair(
                                &circ,
                            )
                            .expect("failed to create halo2 keypair");
                        });
                    })
                });
                keypair_benchmarks.finish();

                println!("\n{}-keypair-base/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
            }
            SECTOR_NODES_16_MIB => {
                let start = Instant::now();
                let circ = SdrPorepCircuit::<Fp, U8, U2, U0, SECTOR_NODES_16_MIB>::blank_circuit();
                println!("\n{}-keypair-base-BlankCircuit/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let start = Instant::now();
                let _keypair = <StackedDrg<
                    '_,
                    MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U2, U0>,
                    DefaultPieceHasher<Fp>,
                > as halo2::CompoundProof<Fp, SECTOR_NODES_16_MIB>>::create_keypair(
                    &circ
                )
                .expect("failed to create halo2 keypair");
                println!("\n{}-keypair-base-FirstTime/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let mut keypair_benchmarks =
                    c.benchmark_group(format!("{}-keypair-base", benchmark_prefix));
                keypair_benchmarks.sample_size(10);
                let start = Instant::now();
                keypair_benchmarks.bench_function("Halo2Keypair::create", |b| {
                    b.iter(|| {
                        black_box({
                            <StackedDrg<
                                '_,
                                MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U2, U0>,
                                DefaultPieceHasher<Fp>,
                            > as halo2::CompoundProof<Fp, SECTOR_NODES_16_MIB>>::create_keypair(
                                &circ,
                            )
                            .expect("failed to create halo2 keypair");
                        });
                    })
                });
                keypair_benchmarks.finish();

                println!("\n{}-keypair-base/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
            }
            _ => panic!("Unsupported leaf_count"),
        };
    }
}

#[allow(clippy::unit_arg)]
fn bench_halo2_keypair_sub_8(c: &mut Criterion) {
    let leaf_counts = vec![SECTOR_NODES_16_KIB, SECTOR_NODES_32_GIB];
    for leaf_count in leaf_counts {
        let sector_bytes = 32 * leaf_count;
        let benchmark_prefix = format!(
            "merkle-poseidon-arity={}-{}-{}/leaves={}/sector_size={}",
            8, 8, 0, leaf_count, sector_bytes
        );

        match leaf_count {
            SECTOR_NODES_16_KIB => {
                let start = Instant::now();
                let circ = SdrPorepCircuit::<Fp, U8, U8, U0, SECTOR_NODES_16_KIB>::blank_circuit();
                println!("\n{}-keypair-base-BlankCircuit/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let start = Instant::now();
                let _keypair = <StackedDrg<
                    '_,
                    MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U8, U0>,
                    DefaultPieceHasher<Fp>,
                > as halo2::CompoundProof<Fp, SECTOR_NODES_16_KIB>>::create_keypair(
                    &circ
                )
                .expect("failed to create halo2 keypair");
                println!("\n{}-keypair-base-FirstTime/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let mut keypair_benchmarks =
                    c.benchmark_group(format!("{}-keypair-base", benchmark_prefix));
                keypair_benchmarks.sample_size(10);
                let start = Instant::now();
                keypair_benchmarks.bench_function("Halo2Keypair::create", |b| {
                    b.iter(|| {
                        black_box({
                            <StackedDrg<
                                '_,
                                MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U8, U0>,
                                DefaultPieceHasher<Fp>,
                            > as halo2::CompoundProof<Fp, SECTOR_NODES_16_KIB>>::create_keypair(
                                &circ,
                            )
                            .expect("failed to create halo2 keypair");
                        });
                    })
                });
                keypair_benchmarks.finish();

                println!("\n{}-keypair-base/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
            }
            SECTOR_NODES_32_GIB => {
                let start = Instant::now();
                let circ = SdrPorepCircuit::<Fp, U8, U8, U0, SECTOR_NODES_32_GIB>::blank_circuit();
                println!(
                    "\n{}-keypair-base-BlankCircuit/halo2-k={}",
                    benchmark_prefix,
                    circ.k()
                );
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let start = Instant::now();
                let _keypair = <StackedDrg<
                    '_,
                    MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U8, U0>,
                    DefaultPieceHasher<Fp>,
                > as halo2::CompoundProof<Fp, SECTOR_NODES_32_GIB>>::create_keypair(
                    &circ
                )
                .expect("failed to create halo2 keypair");
                println!("\n{}-keypair-base-FirstTime/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

                let mut keypair_benchmarks =
                    c.benchmark_group(format!("{}-keypair-base", benchmark_prefix));
                keypair_benchmarks.sample_size(10);
                let start = Instant::now();
                keypair_benchmarks.bench_function("Halo2Keypair::create", |b| {
                    b.iter(|| {
                        black_box({
                            <StackedDrg<
                                '_,
                                MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U8, U0>,
                                DefaultPieceHasher<Fp>,
                            > as halo2::CompoundProof<Fp, SECTOR_NODES_32_GIB>>::create_keypair(
                                &circ,
                            )
                            .expect("failed to create halo2 keypair");
                        });
                    })
                });
                keypair_benchmarks.finish();

                println!("\n{}-keypair-base/halo2", benchmark_prefix);
                println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
            }
            _ => panic!("Unsupported leaf_count"),
        };
    }
}

#[allow(clippy::unit_arg)]
fn bench_halo2_keypair_top_2(c: &mut Criterion) {
    let leaf_count = SECTOR_NODES_64_GIB;
    let sector_bytes = 32 * leaf_count;
    let benchmark_prefix = format!(
        "merkle-poseidon-arity={}-{}-{}/leaves={}/sector_size={}",
        8, 8, 2, leaf_count, sector_bytes
    );

    let start = Instant::now();
    let circ = SdrPorepCircuit::<Fp, U8, U8, U2, SECTOR_NODES_64_GIB>::blank_circuit();
    println!("\n{}-keypair-base-BlankCircuit/halo2", benchmark_prefix);
    println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

    let start = Instant::now();
    let _keypair = <StackedDrg<
        '_,
        MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U8, U2>,
        DefaultPieceHasher<Fp>,
    > as halo2::CompoundProof<Fp, SECTOR_NODES_64_GIB>>::create_keypair(&circ)
    .expect("failed to create halo2 keypair");
    println!("\n{}-keypair-base-FirstTime/halo2", benchmark_prefix);
    println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());

    let mut keypair_benchmarks = c.benchmark_group(format!("{}-keypair-base", benchmark_prefix));
    keypair_benchmarks.sample_size(10);
    let start = Instant::now();
    keypair_benchmarks.bench_function("Halo2Keypair::create", |b| {
        b.iter(|| {
            black_box({
                <StackedDrg<
                    '_,
                    MerkleTreeWrapper<DefaultTreeHasher<Fp>, MockStore, U8, U8, U2>,
                    DefaultPieceHasher<Fp>,
                > as halo2::CompoundProof<Fp, SECTOR_NODES_64_GIB>>::create_keypair(
                    &circ
                )
                .expect("failed to create halo2 keypair");
            });
        })
    });
    keypair_benchmarks.finish();

    println!("\n{}-keypair-base/halo2", benchmark_prefix);
    println!("\t\t\ttime:\t{}s", start.elapsed().as_secs_f32());
}

criterion_group!(
    benches,
    bench_halo2_keypair_base,
    bench_halo2_keypair_sub_2,
    bench_halo2_keypair_sub_8,
    bench_halo2_keypair_top_2,
);
criterion_main!(benches);
