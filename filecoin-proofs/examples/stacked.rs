#[macro_use]
extern crate clap;
#[cfg(any(feature = "cpu-profile", feature = "heap-profile"))]
extern crate gperftools;
#[macro_use]
extern crate log;

use chrono::Utc;
use clap::{App, Arg};
#[cfg(feature = "heap-profile")]
use gperftools::heap_profiler::HEAP_PROFILER;
#[cfg(feature = "cpu-profile")]
use gperftools::profiler::PROFILER;
use memmap::MmapMut;
use memmap::MmapOptions;
use paired::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::time::{Duration, Instant};
use std::u32;

use bellperson::Circuit;
use fil_sapling_crypto::jubjub::JubjubBls12;

use storage_proofs::circuit::metric::*;
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgporep;
use storage_proofs::drgraph::*;
use storage_proofs::example_helper::prettyb;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::{Blake2sHasher, Hasher, PedersenHasher, Sha256Hasher};
use storage_proofs::porep::PoRep;
use storage_proofs::proof::ProofScheme;
use storage_proofs::settings;
use storage_proofs::stacked::{
    self, ChallengeRequirements, LayerChallenges, StackedDrg, EXP_DEGREE,
};

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
            .open(format!("./random-stacked-data-{:?}", Utc::now()))
            .unwrap()
    };
    info!("generating fake data");

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
            .open(format!("./stacked-data-{:?}", Utc::now()))
            .unwrap()
    };

    info!("generating zeroed data");
    file.set_len(32 * n as u64).unwrap();

    unsafe { MmapOptions::new().map_mut(&file).unwrap() }
}

pub fn file_backed_mmap_from(data: &[u8]) -> MmapMut {
    let mut tmpfile: File = tempfile::tempfile().unwrap();
    tmpfile.write_all(data).unwrap();

    unsafe { MmapOptions::new().map_mut(&tmpfile).unwrap() }
}

fn dump_proof_bytes<H: Hasher>(all_partition_proofs: &[Vec<stacked::Proof<H>>]) {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!("./proofs-{:?}", Utc::now()))
        .unwrap();
    info!("dumping {} proofs", all_partition_proofs.len());

    if let Err(e) = serde_json::to_writer(file, all_partition_proofs) {
        warn!("Encountered error while writing serialized proofs: {}", e);
    }
}

fn do_the_work<H: 'static>(
    data_size: usize,
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

    let m = BASE_DEGREE;
    let expansion_degree = EXP_DEGREE;

    info!("data size: {}", prettyb(data_size));
    info!("m: {}", m);
    info!("expansion_degree: {}", expansion_degree);
    info!("layer_challenges: {:?}", layer_challenges);
    info!("layers: {}", layer_challenges.layers());
    info!("partitions: {}", partitions);
    info!("circuit: {:?}", circuit);
    info!("groth: {:?}", groth);
    info!("bench: {:?}", bench);

    let nodes = data_size / 32;

    let replica_id: H::Domain = rng.gen();
    let sp = stacked::SetupParams {
        drg: drgporep::DrgParams {
            nodes,
            degree: m,
            expansion_degree,
            seed: new_seed(),
        },
        layer_challenges: layer_challenges.clone(),
    };

    info!("running setup");
    start_profile("setup");
    let pp = StackedDrg::<H>::setup(&sp).unwrap();
    info!("setup complete");
    stop_profile();

    let samples: u32 = 5;
    let mut total_proving = Duration::new(0, 0);

    let (pub_in, priv_in, d) = if bench_only {
        (None, None, None)
    } else {
        let mut data = file_backed_mmap_from_zeroes(nodes, use_tmp);

        let start = Instant::now();
        let mut replication_duration = Duration::new(0, 0);

        info!("running replicate");

        start_profile("replicate");
        let (tau, (p_aux, t_aux)) =
            StackedDrg::<H>::replicate(&pp, &replica_id, &mut data, None).unwrap();
        stop_profile();
        let pub_inputs = stacked::PublicInputs::<H::Domain> {
            replica_id,
            tau: Some(tau.clone()),
            k: Some(0),
            seed: None,
        };

        let priv_inputs = stacked::PrivateInputs { p_aux, t_aux };

        replication_duration += start.elapsed();

        info!("replication_time: {:?}", replication_duration);

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
        info!("replication_time/byte: {:?}", time_per_byte);
        info!("replication_time/GiB: {:?}", (1 << 30) * time_per_byte);

        info!("generating {} partition proofs", partitions);

        let start = Instant::now();
        start_profile("prove");
        let all_partition_proofs =
            StackedDrg::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions)
                .expect("failed to prove");
        stop_profile();
        let vanilla_proving = start.elapsed();
        total_proving += vanilla_proving;

        info!("vanilla_proving_time: {:?}", vanilla_proving);
        if dump_proofs {
            dump_proof_bytes(&all_partition_proofs);
        }

        info!("sampling verifying (samples: {})", samples);
        let mut total_verifying = Duration::new(0, 0);

        start_profile("verify");
        for _ in 0..samples {
            let start = Instant::now();
            let verified =
                StackedDrg::<H>::verify_all_partitions(&pp, &pub_inputs, &all_partition_proofs)
                    .expect("failed during verification");
            if !verified {
                info!("Verification failed.");
            };
            total_verifying += start.elapsed();
        }
        info!("Verification complete");
        stop_profile();

        let verifying_avg = total_verifying / samples;
        let verifying_avg = f64::from(verifying_avg.subsec_nanos()) / 1_000_000_000f64
            + (verifying_avg.as_secs() as f64);
        info!(
            "average_vanilla_verifying_time: {:?} seconds",
            verifying_avg
        );

        (Some(pub_inputs), Some(priv_inputs), Some(data))
    };

    if circuit || groth || bench {
        let window_size = settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size;
        let engine_params = JubjubBls12::new_with_window_size(window_size);
        let compound_public_params = compound_proof::PublicParams {
            vanilla_params: pp.clone(),
            engine_params: &engine_params,
            partitions: Some(partitions),
        };
        if circuit || bench {
            info!("Performing circuit bench.");
            let mut cs = MetricCS::<Bls12>::new();

            StackedCompound::blank_circuit(&pp, &engine_params)
                .synthesize(&mut cs)
                .expect("failed to synthesize circuit");

            info!("circuit_num_inputs: {}", cs.num_inputs());
            info!("circuit_num_constraints: {}", cs.num_constraints());

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
            info!("Performing circuit groth.");
            let gparams = StackedCompound::groth_params(
                &compound_public_params.vanilla_params,
                &engine_params,
            )
            .unwrap();

            let multi_proof = {
                let start = Instant::now();
                start_profile("groth-prove");
                let result = StackedCompound::prove(
                    &compound_public_params,
                    &pub_inputs,
                    &priv_inputs,
                    &gparams,
                )
                .unwrap();
                stop_profile();
                let groth_proving = start.elapsed();
                info!("groth_proving_time: {:?} seconds", groth_proving);
                total_proving += groth_proving;
                info!("combined_proving_time: {:?} seconds", total_proving);
                result
            };
            info!("sampling groth verifying (samples: {})", samples);
            let verified = {
                let mut total_groth_verifying = Duration::new(0, 0);
                let mut result = true;
                start_profile("groth-verify");
                for _ in 0..samples {
                    let start = Instant::now();
                    let cur_result = result;
                    StackedCompound::verify(
                        &compound_public_params,
                        &pub_inputs,
                        &multi_proof,
                        &ChallengeRequirements {
                            minimum_challenges: 1,
                        },
                    )
                    .unwrap();
                    // If one verification fails, result becomes permanently false.
                    result = result && cur_result;
                    total_groth_verifying += start.elapsed();
                }
                stop_profile();
                let avg_groth_verifying = total_groth_verifying / samples;
                info!(
                    "average_groth_verifying_time: {:?} seconds",
                    avg_groth_verifying
                );
                result
            };
            assert!(verified);
        }
    }

    if let Some(data) = d {
        if extract {
            let start = Instant::now();
            info!("Extracting.");
            start_profile("extract");
            let decoded_data = StackedDrg::<H>::extract_all(&pp, &replica_id, &data).unwrap();
            stop_profile();
            let extracting = start.elapsed();
            info!("extracting_time: {:?}", extracting);

            assert_ne!(&(*data), decoded_data.as_slice());
        }
    }
}

fn main() {
    pretty_env_logger::init_timed();

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
            Arg::with_name("bench")
                .long("bench")
                .help("Synthesize and report inputs/constraints for a circuit.")
        )
        .arg(
            Arg::with_name("bench-only")
                .long("bench-only")
                .help("Don't replicate or perform Groth proving.")
                .conflicts_with_all(&["groth", "extract"])
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
        .get_matches();

    let data_size = value_t!(matches, "size", usize).unwrap() * 1024;
    let challenge_count = value_t!(matches, "challenges", usize).unwrap();
    let hasher = value_t!(matches, "hasher", String).unwrap();
    let layers = value_t!(matches, "layers", usize).unwrap();
    let partitions = value_t!(matches, "partitions", usize).unwrap();
    let use_tmp = !matches.is_present("no-tmp");
    let dump_proofs = matches.is_present("dump");
    let groth = matches.is_present("groth");
    let bench = matches.is_present("bench");
    let bench_only = matches.is_present("bench-only");
    let circuit = matches.is_present("circuit");
    let extract = matches.is_present("extract");

    let challenges = LayerChallenges::new(layers, challenge_count);

    info!("hasher: {}", hasher);
    match hasher.as_ref() {
        "pedersen" => {
            do_the_work::<PedersenHasher>(
                data_size,
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
