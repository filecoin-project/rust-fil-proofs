extern crate bellman;
extern crate chrono;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
#[macro_use]
extern crate clap;
#[cfg(any(feature = "cpu-profile", feature = "heap-profile"))]
extern crate gperftools;
extern crate memmap;
extern crate serde_json;
extern crate tempfile;
#[macro_use]
extern crate slog;

extern crate filecoin_proofs;
extern crate storage_proofs;

use chrono::Utc;
use clap::{App, Arg};
#[cfg(feature = "heap-profile")]
use gperftools::heap_profiler::HEAP_PROFILER;
#[cfg(feature = "cpu-profile")]
use gperftools::profiler::PROFILER;
use memmap::MmapMut;
use memmap::MmapOptions;
use pairing::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant};
use std::u32;

use bellman::Circuit;
use sapling_crypto::jubjub::JubjubBls12;

use storage_proofs::circuit::metric::*;
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgporep;
use storage_proofs::drgraph::*;
use storage_proofs::example_helper::prettyb;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::{Blake2sHasher, Hasher, PedersenHasher, Sha256Hasher};
use storage_proofs::layered_drgporep::{self, LayerChallenges};
use storage_proofs::porep::PoRep;
use storage_proofs::proof::ProofScheme;
use storage_proofs::zigzag_drgporep::*;

use filecoin_proofs::FCP_LOG;

// We can only one of the profilers at a time, either CPU (`profile`)
// or memory (`heap-profile`), duplicating the function so they won't
// be built together.
#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    PROFILER
        .lock()
        .unwrap()
        .start(format!("./{}.profile", stage))
        .unwrap();
}

#[cfg(feature = "heap-profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    HEAP_PROFILER
        .lock()
        .unwrap()
        .start(format!("./{}.heap-profile", stage))
        .unwrap();
}

#[cfg(not(any(feature = "cpu-profile", feature = "heap-profile")))]
#[inline(always)]
fn start_profile(_stage: &str) {}

#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn stop_profile() {
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(feature = "heap-profile")]
#[inline(always)]
fn stop_profile() {
    HEAP_PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(any(feature = "cpu-profile", feature = "heap-profile")))]
#[inline(always)]
fn stop_profile() {}

fn _file_backed_mmap_from_random_bytes(n: usize, use_tmp: bool) -> MmapMut {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let mut file: File = if use_tmp {
        tempfile::tempfile().unwrap()
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(format!("./random-zigzag-data-{:?}", Utc::now()))
            .unwrap()
    };
    info!(FCP_LOG, "generating fake data"; "target" => "status");

    for _ in 0..n {
        file.write_all(&fr_into_bytes::<Bls12>(&rng.gen())).unwrap();
    }

    unsafe { MmapOptions::new().map_mut(&file).unwrap() }
}

fn file_backed_mmap_from_zeroes(n: usize, use_tmp: bool) -> MmapMut {
    let file: File = if use_tmp {
        tempfile::tempfile().unwrap()
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(format!("./zigzag-data-{:?}", Utc::now()))
            .unwrap()
    };

    info!(FCP_LOG, "generating zeroed data"; "target" => "status");
    file.set_len(32 * n as u64).unwrap();

    unsafe { MmapOptions::new().map_mut(&file).unwrap() }
}

pub fn file_backed_mmap_from(data: &[u8]) -> MmapMut {
    let mut tmpfile: File = tempfile::tempfile().unwrap();
    tmpfile.write_all(data).unwrap();

    unsafe { MmapOptions::new().map_mut(&tmpfile).unwrap() }
}

fn dump_proof_bytes<H: Hasher>(all_partition_proofs: &[layered_drgporep::Proof<H>]) {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!("./proofs-{:?}", Utc::now()))
        .unwrap();
    info!(
        FCP_LOG,
        "dumping {} proofs",
        all_partition_proofs.len(); "target" => "status"
    );

    if let Err(e) = serde_json::to_writer(file, all_partition_proofs) {
        warn!(
            FCP_LOG,
            "Encountered error while writing serialized proofs: {}", e
        );
    }
}

fn do_the_work<H: 'static>(
    data_size: usize,
    m: usize,
    expansion_degree: usize,
    sloth_iter: usize,
    layer_challenges: LayerChallenges,
    partitions: usize,
    circuit: bool,
    groth: bool,
    bench: bool,
    extract: bool,
    use_tmp: bool,
    dump_proofs: bool,
    bench_only: bool,
) where
    H: Hasher,
{
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    info!(FCP_LOG, "data size: {}", prettyb(data_size); "target" => "config");
    info!(FCP_LOG, "m: {}", m; "target" => "config");
    info!(FCP_LOG, "expansion_degree: {}", expansion_degree; "target" => "config");
    info!(FCP_LOG, "sloth: {}", sloth_iter; "target" => "config");
    info!(FCP_LOG, "layer_challenges: {:?}", layer_challenges; "target" => "config");
    info!(FCP_LOG, "all_challenges: {:?}", layer_challenges.all_challenges(); "target" => "config");
    info!(FCP_LOG, "total_challenges: {:?}", layer_challenges.total_challenges(); "target" => "config");
    info!(FCP_LOG, "layers: {}", layer_challenges.layers(); "target" => "config");
    info!(FCP_LOG, "partitions: {}", partitions; "target" => "config");
    info!(FCP_LOG, "circuit: {:?}", circuit; "target" => "config");
    info!(FCP_LOG, "groth: {:?}", groth; "target" => "config");
    info!(FCP_LOG, "bench: {:?}", bench; "target" => "config");

    let nodes = data_size / 32;

    let replica_id: H::Domain = rng.gen();
    let sp = layered_drgporep::SetupParams {
        drg: drgporep::DrgParams {
            nodes,
            degree: m,
            expansion_degree,
            seed: new_seed(),
        },
        sloth_iter,
        layer_challenges: layer_challenges.clone(),
    };

    info!(FCP_LOG, "running setup");
    start_profile("setup");
    let pp = ZigZagDrgPoRep::<H>::setup(&sp).unwrap();
    info!(FCP_LOG, "setup complete");
    stop_profile();

    let samples: u32 = 5;
    let mut total_proving = Duration::new(0, 0);

    let (pub_in, priv_in, d) = if bench_only {
        (None, None, None)
    } else {
        let mut data = file_backed_mmap_from_zeroes(nodes, use_tmp);

        let start = Instant::now();
        let mut replication_duration = Duration::new(0, 0);

        info!(FCP_LOG, "running replicate");

        start_profile("replicate");
        let (tau, aux) = ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, &mut data, None).unwrap();
        stop_profile();
        let pub_inputs = layered_drgporep::PublicInputs::<H::Domain> {
            replica_id,
            tau: Some(tau.simplify().into()),
            comm_r_star: tau.comm_r_star,
            k: Some(0),
        };

        let priv_inputs = layered_drgporep::PrivateInputs {
            aux,
            tau: tau.layer_taus,
        };

        replication_duration += start.elapsed();

        info!(FCP_LOG, "replication_time: {:?}", replication_duration; "target" => "stats");

        let time_per_byte = if data_size > (u32::MAX as usize) {
            // Duration only supports division by u32, so if data_size (of type usize) is larger,
            // we have to jump through some hoops to get the value we want, which is duration / size.
            // Consider: x = size / max
            //           y = duration / x = duration * max / size
            //           y / max = duration * max / size * max = duration / size
            let x = data_size as f64 / u32::MAX as f64;
            let y = replication_duration / x as u32;
            y / u32::MAX
        } else {
            replication_duration / (data_size as u32)
        };
        info!(
            FCP_LOG,
            "replication_time/byte: {:?}",
            time_per_byte; "target" => "stats"
        );
        info!(
            FCP_LOG,
            "replication_time/GiB: {:?}",
            (1 << 30) * time_per_byte; "target" => "stats"
        );

        info!(FCP_LOG, "generating {} partition proofs", partitions);

        let start = Instant::now();
        start_profile("prove");
        let all_partition_proofs =
            ZigZagDrgPoRep::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions)
                .expect("failed to prove");
        stop_profile();
        let vanilla_proving = start.elapsed();
        total_proving += vanilla_proving;

        info!(FCP_LOG, "vanilla_proving_time: {:?}", vanilla_proving; "target" => "stats");
        if dump_proofs {
            dump_proof_bytes(&all_partition_proofs);
        }

        info!(FCP_LOG, "sampling verifying (samples: {})", samples);
        let mut total_verifying = Duration::new(0, 0);

        start_profile("verify");
        for _ in 0..samples {
            let start = Instant::now();
            let verified =
                ZigZagDrgPoRep::<H>::verify_all_partitions(&pp, &pub_inputs, &all_partition_proofs)
                    .expect("failed during verification");
            if !verified {
                info!(FCP_LOG, "Verification failed."; "target" => "results");
            };
            total_verifying += start.elapsed();
        }
        info!(FCP_LOG, "Verification complete"; "target" => "status");
        stop_profile();

        let verifying_avg = total_verifying / samples;
        let verifying_avg = f64::from(verifying_avg.subsec_nanos()) / 1_000_000_000f64
            + (verifying_avg.as_secs() as f64);
        info!(FCP_LOG, "average_vanilla_verifying_time: {:?} seconds", verifying_avg; "target" => "stats");

        (Some(pub_inputs), Some(priv_inputs), Some(data))
    };

    if circuit || groth || bench {
        let engine_params = JubjubBls12::new();
        let compound_public_params = compound_proof::PublicParams {
            vanilla_params: pp.clone(),
            engine_params: &engine_params,
            partitions: Some(partitions),
        };
        if circuit || bench {
            info!(FCP_LOG, "Performing circuit bench."; "target" => "status");
            let mut cs = MetricCS::<Bls12>::new();

            ZigZagCompound::blank_circuit(&pp, &engine_params)
                .synthesize(&mut cs)
                .expect("failed to synthesize circuit");

            info!(FCP_LOG, "circuit_num_inputs: {}", cs.num_inputs(); "target" => "stats");
            info!(FCP_LOG, "circuit_num_constraints: {}", cs.num_constraints(); "target" => "stats");

            if circuit {
                println!("{}", cs.pretty_print());
            }
        }

        if groth {
            let pub_inputs = pub_in.unwrap();
            let priv_inputs = priv_in.unwrap();

            // TODO: The time measured for Groth proving also includes parameter loading (which can be long)
            // and vanilla proving, which may also be.
            // For now, analysis should note and subtract out these times.
            // We should implement a method of CompoundProof, which will skip vanilla proving.
            // We should also allow the serialized vanilla proofs to be passed (as a file) to the example
            // and skip replication/vanilla-proving entirely.
            info!(FCP_LOG, "Performing circuit groth."; "target" => "status");
            let gparams = ZigZagCompound::groth_params(
                &compound_public_params.vanilla_params,
                &engine_params,
            )
            .unwrap();

            let multi_proof = {
                let start = Instant::now();
                start_profile("groth-prove");
                let result = ZigZagCompound::prove(
                    &compound_public_params,
                    &pub_inputs,
                    &priv_inputs,
                    &gparams,
                )
                .unwrap();
                stop_profile();
                let groth_proving = start.elapsed();
                info!(FCP_LOG, "groth_proving_time: {:?} seconds", groth_proving; "target" => "stats");
                total_proving += groth_proving;
                info!(FCP_LOG, "combined_proving_time: {:?} seconds", total_proving; "target" => "stats");
                result
            };
            info!(FCP_LOG, "sampling groth verifying (samples: {})", samples);
            let verified = {
                let mut total_groth_verifying = Duration::new(0, 0);
                let mut result = true;
                start_profile("groth-verify");
                for _ in 0..samples {
                    let start = Instant::now();
                    let cur_result = result;
                    ZigZagCompound::verify(&compound_public_params, &pub_inputs, &multi_proof)
                        .unwrap();
                    // If one verification fails, result becomes permanently false.
                    result = result && cur_result;
                    total_groth_verifying += start.elapsed();
                }
                stop_profile();
                let avg_groth_verifying = total_groth_verifying / samples;
                info!(FCP_LOG, "average_groth_verifying_time: {:?} seconds", avg_groth_verifying; "target" => "stats");
                result
            };
            assert!(verified);
        }
    }

    if let Some(data) = d {
        if extract {
            let start = Instant::now();
            info!(FCP_LOG, "Extracting.");
            start_profile("extract");
            let decoded_data = ZigZagDrgPoRep::<H>::extract_all(&pp, &replica_id, &data).unwrap();
            stop_profile();
            let extracting = start.elapsed();
            info!(FCP_LOG, "extracting_time: {:?}", extracting; "target" => "stats");

            assert_eq!(&(*data), decoded_data.as_slice());
        }
    }
}

fn main() {
    let matches = App::new(stringify!("DrgPoRep Vanilla Bench"))
        .version("1.0")
        .arg(
            Arg::with_name("size")
                .required(true)
                .long("size")
                .help("The data size in KB")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("m")
                .help("The size of m")
                .long("m")
                .default_value("5")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("exp")
                .help("Expansion degree")
                .long("expansion")
                .default_value("8")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sloth")
                .help("The number of sloth iterations")
                .long("sloth")
                .default_value("0")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("challenges")
                .long("challenges")
                .help("How many challenges to execute")
                .default_value("1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("hasher")
                .long("hasher")
                .help("Which hasher should be used.Available: \"pedersen\", \"sha256\", \"blake2s\" (default \"pedersen\")")
                .default_value("pedersen")
                .takes_value(true),
        )
       .arg(
            Arg::with_name("layers")
                .long("layers")
                .help("How many layers to use")
                .default_value("10")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("no-tmp")
                .long("no-tmp")
                .help("Don't use a temp file for random data (write to current directory instead).")
        )
        .arg(
            Arg::with_name("dump")
                .long("dump")
                .help("Dump vanilla proofs to current directory.")
        )
       .arg(
            Arg::with_name("partitions")
                .long("partitions")
                .help("How many circuit partitions to use")
                .default_value("1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("groth")
                .long("groth")
                .help("Generate and verify a groth circuit proof.")
        )
        .arg(
            Arg::with_name("no-bench")
                .long("no-bench")
                .help("Don't synthesize and report inputs/constraints for a circuit.")
        )
        .arg(
            Arg::with_name("bench-only")
                .long("bench-only")
                .help("Don't replicate or perform Groth proving.")
                .conflicts_with_all(&["no-bench", "groth", "extract"])
        )

        .arg(
            Arg::with_name("circuit")
                .long("circuit")
                .help("Print the constraint system.")
        )
        .arg(
            Arg::with_name("extract")
                .long("extract")
                .help("Extract data after proving and verifying.")
        )
        .arg(
            Arg::with_name("taper")
                .long("taper")
                .help("fraction of challenges by which to taper at each layer")
                .default_value("0.0")
        )
        .arg(
            Arg::with_name("taper-layers")
                .long("taper-layers")
                .help("number of layers to taper")
                .takes_value(true)
        )

        .get_matches();

    let data_size = value_t!(matches, "size", usize).unwrap() * 1024;
    let m = value_t!(matches, "m", usize).unwrap();
    let expansion_degree = value_t!(matches, "exp", usize).unwrap();
    let sloth_iter = value_t!(matches, "sloth", usize).unwrap();
    let challenge_count = value_t!(matches, "challenges", usize).unwrap();
    let hasher = value_t!(matches, "hasher", String).unwrap();
    let layers = value_t!(matches, "layers", usize).unwrap();
    let partitions = value_t!(matches, "partitions", usize).unwrap();
    let taper = value_t!(matches, "taper", f64).unwrap();
    let taper_layers = value_t!(matches, "taper-layers", usize).unwrap_or(layers);
    let use_tmp = !matches.is_present("no-tmp");
    let dump_proofs = matches.is_present("dump");
    let groth = matches.is_present("groth");
    let bench = !matches.is_present("no-bench");
    let bench_only = matches.is_present("bench-only");
    let circuit = matches.is_present("circuit");
    let extract = matches.is_present("extract");

    let challenges = if taper == 0.0 {
        LayerChallenges::new_fixed(layers, challenge_count)
    } else {
        LayerChallenges::new_tapered(layers, challenge_count, taper_layers, taper)
    };

    info!(FCP_LOG, "hasher: {}", hasher; "target" => "config");
    match hasher.as_ref() {
        "pedersen" => {
            do_the_work::<PedersenHasher>(
                data_size,
                m,
                expansion_degree,
                sloth_iter,
                challenges,
                partitions,
                circuit,
                groth,
                bench,
                extract,
                use_tmp,
                dump_proofs,
                bench_only,
            );
        }
        "sha256" => {
            do_the_work::<Sha256Hasher>(
                data_size,
                m,
                expansion_degree,
                sloth_iter,
                challenges,
                partitions,
                circuit,
                groth,
                bench,
                extract,
                use_tmp,
                dump_proofs,
                bench_only,
            );
        }
        "blake2s" => {
            do_the_work::<Blake2sHasher>(
                data_size,
                m,
                expansion_degree,
                sloth_iter,
                challenges,
                partitions,
                circuit,
                groth,
                bench,
                extract,
                use_tmp,
                dump_proofs,
                bench_only,
            );
        }
        _ => panic!(format!("invalid hasher: {}", hasher)),
    }
}
