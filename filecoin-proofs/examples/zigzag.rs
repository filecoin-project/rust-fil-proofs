extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
#[macro_use]
extern crate clap;
#[cfg(feature = "profile")]
extern crate gperftools;
extern crate memmap;
extern crate tempfile;
#[macro_use]
extern crate slog;

extern crate filecoin_proofs;
extern crate storage_proofs;

use clap::{App, Arg};
#[cfg(feature = "profile")]
use gperftools::profiler::PROFILER;
use memmap::MmapMut;
use memmap::MmapOptions;
use pairing::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

use bellman::Circuit;
use sapling_crypto::jubjub::JubjubBls12;

use storage_proofs::circuit::test::*;
use storage_proofs::circuit::zigzag::{ZigZagCircuit, ZigZagCompound};
use storage_proofs::compound_proof::{self, CircuitComponent, CompoundProof};
use storage_proofs::drgporep;
use storage_proofs::drgraph::*;
use storage_proofs::example_helper::prettyb;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::{Blake2sHasher, Hasher, PedersenHasher, Sha256Hasher};
use storage_proofs::layered_drgporep;
use storage_proofs::porep::PoRep;
use storage_proofs::proof::ProofScheme;
use storage_proofs::zigzag_drgporep::*;

use filecoin_proofs::FCP_LOG;

#[cfg(feature = "profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    PROFILER
        .lock()
        .unwrap()
        .start(format!("./{}.profile", stage))
        .unwrap();
}

#[cfg(not(feature = "profile"))]
#[inline(always)]
fn start_profile(_stage: &str) {}

#[cfg(feature = "profile")]
#[inline(always)]
fn stop_profile() {
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(feature = "profile"))]
#[inline(always)]
fn stop_profile() {}

fn file_backed_mmap_from_random_bytes(n: usize) -> MmapMut {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let mut tmpfile: File = tempfile::tempfile().unwrap();

    for _ in 0..n {
        tmpfile
            .write_all(&fr_into_bytes::<Bls12>(&rng.gen()))
            .unwrap();
    }

    unsafe { MmapOptions::new().map_mut(&tmpfile).unwrap() }
}

pub fn file_backed_mmap_from(data: &[u8]) -> MmapMut {
    let mut tmpfile: File = tempfile::tempfile().unwrap();
    tmpfile.write_all(data).unwrap();

    unsafe { MmapOptions::new().map_mut(&tmpfile).unwrap() }
}

fn do_the_work<H: 'static>(
    data_size: usize,
    m: usize,
    expansion_degree: usize,
    sloth_iter: usize,
    challenge_count: usize,
    layers: usize,
    partitions: usize,
    circuit: bool,
    groth: bool,
    bench: bool,
    extract: bool,
) where
    H: Hasher,
{
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    info!(FCP_LOG, "data size: {}", prettyb(data_size); "target" => "config");
    info!(FCP_LOG, "m: {}", m; "target" => "config");
    info!(FCP_LOG, "expansion_degree: {}", expansion_degree; "target" => "config");
    info!(FCP_LOG, "sloth: {}", sloth_iter; "target" => "config");
    info!(FCP_LOG, "challenge_count: {}", challenge_count; "target" => "config");
    info!(FCP_LOG, "layers: {}", layers; "target" => "config");
    info!(FCP_LOG, "partitions: {}", partitions; "target" => "config");
    info!(FCP_LOG, "circuit: {:?}", circuit; "target" => "config");
    info!(FCP_LOG, "groth: {:?}", groth; "target" => "config");
    info!(FCP_LOG, "bench: {:?}", bench; "target" => "config");

    info!(FCP_LOG, "generating fake data"; "target" => "status");

    let nodes = data_size / 32;

    let data = file_backed_mmap_from_random_bytes(nodes);

    let replica_id: H::Domain = rng.gen();
    let mut data_copy = file_backed_mmap_from(&data);
    let sp = layered_drgporep::SetupParams {
        drg_porep_setup_params: drgporep::SetupParams {
            drg: drgporep::DrgParams {
                nodes,
                degree: m,
                expansion_degree,
                seed: new_seed(),
            },
            sloth_iter,
        },
        layers,
        challenge_count,
    };

    info!(FCP_LOG, "running setup");
    start_profile("setup");
    let pp = ZigZagDrgPoRep::<H>::setup(&sp).unwrap();
    stop_profile();

    let start = Instant::now();
    let mut replication_duration = Duration::new(0, 0);

    info!(FCP_LOG, "running replicate");

    start_profile("replicate");
    let (tau, aux) =
        ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, &mut data_copy, None).unwrap();
    stop_profile();
    let pub_inputs = layered_drgporep::PublicInputs::<H::Domain> {
        replica_id,
        challenge_count,
        tau: Some(tau.simplify().into()),
        comm_r_star: tau.comm_r_star,
        k: Some(0),
    };

    let priv_inputs = layered_drgporep::PrivateInputs {
        replica: &data,
        aux,
        tau: tau.layer_taus,
    };

    replication_duration += start.elapsed();

    info!(FCP_LOG, "replication_time: {:?}", replication_duration; "target" => "stats");
    info!(
        FCP_LOG,
        "replication_time/byte: {:?}",
        replication_duration / data_size as u32; "target" => "stats"
    );
    info!(
        FCP_LOG,
        "replication_time/GiB: {:?}",
        (1 << 30) * replication_duration / data_size as u32; "target" => "stats"
    );

    let mut total_proving = Duration::new(0, 0);
    info!(FCP_LOG, "generating one proof");

    let start = Instant::now();
    start_profile("prove");
    let all_partition_proofs =
        ZigZagDrgPoRep::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions)
            .expect("failed to prove");
    stop_profile();
    let vanilla_proving = start.elapsed();
    total_proving += vanilla_proving;

    let proving_avg = total_proving;
    let proving_avg =
        f64::from(proving_avg.subsec_nanos()) / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    // -- print statistics

    //    let serialized_proofs = proofs.iter().fold(Vec::new(), |mut acc, p| {
    //        acc.extend(p.serialize());
    //        acc
    //    });
    //    let avg_proof_size = serialized_proofs.len() / samples as usize;
    //
    //info!(target: "stats", "Average proof size {}", prettyb(avg_proof_size));

    info!(FCP_LOG, "vanilla_proving_time: {:?} seconds", proving_avg; "target" => "stats");

    let samples: u32 = 5;
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

    if circuit || groth || bench {
        let engine_params = JubjubBls12::new();
        let compound_public_params = compound_proof::PublicParams {
            vanilla_params: pp.clone(),
            engine_params: &engine_params,
            partitions: Some(partitions),
        };
        if circuit || bench {
            info!(FCP_LOG, "Performing circuit bench."; "target" => "status");
            let mut cs = TestConstraintSystem::<Bls12>::new();

            ZigZagCompound::circuit(
                &pub_inputs,
                <ZigZagCircuit<Bls12, H> as CircuitComponent>::ComponentPrivateInputs::default(),
                &all_partition_proofs[0],
                &pp,
                &engine_params,
            )
            .synthesize(&mut cs)
            .expect("failed to synthesize circuit");

            info!(FCP_LOG, "circuit_num_inputs: {}", cs.num_inputs(); "target" => "stats");
            info!(FCP_LOG, "circuit_num_constraints: {}", cs.num_constraints(); "target" => "stats");

            if circuit {
                println!("{}", cs.pretty_print());
            }
        }

        if groth {
            info!(FCP_LOG, "Performing circuit groth."; "target" => "status");
            let multi_proof = {
                // TODO: Make this a macro.
                let start = Instant::now();
                start_profile("groth-prove");
                let result =
                    ZigZagCompound::prove(&compound_public_params, &pub_inputs, &priv_inputs, None)
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

    if extract {
        let start = Instant::now();
        info!(FCP_LOG, "Extracting.");
        start_profile("extract");
        let decoded_data = ZigZagDrgPoRep::<H>::extract_all(&pp, &replica_id, &data_copy).unwrap();
        stop_profile();
        let extracting = start.elapsed();
        info!(FCP_LOG, "extracting_time: {:?}", extracting; "target" => "stats");

        assert_eq!(&(*data), decoded_data.as_slice());
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
                .default_value("6")
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
                .help("Synthesize and report inputs/constraints for a circuit.")
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
    let m = value_t!(matches, "m", usize).unwrap();
    let expansion_degree = value_t!(matches, "exp", usize).unwrap();
    let sloth_iter = value_t!(matches, "sloth", usize).unwrap();
    let challenge_count = value_t!(matches, "challenges", usize).unwrap();
    let hasher = value_t!(matches, "hasher", String).unwrap();
    let layers = value_t!(matches, "layers", usize).unwrap();
    let partitions = value_t!(matches, "partitions", usize).unwrap();
    let groth = matches.is_present("groth");
    let bench = !matches.is_present("no-bench");
    let circuit = matches.is_present("circuit");
    let extract = matches.is_present("extract");

    info!(FCP_LOG, "hasher: {}", hasher; "target" => "config");
    match hasher.as_ref() {
        "pedersen" => {
            do_the_work::<PedersenHasher>(
                data_size,
                m,
                expansion_degree,
                sloth_iter,
                challenge_count,
                layers,
                partitions,
                circuit,
                groth,
                bench,
                extract,
            );
        }
        "sha256" => {
            do_the_work::<Sha256Hasher>(
                data_size,
                m,
                expansion_degree,
                sloth_iter,
                challenge_count,
                layers,
                partitions,
                circuit,
                groth,
                bench,
                extract,
            );
        }
        "blake2s" => {
            do_the_work::<Blake2sHasher>(
                data_size,
                m,
                expansion_degree,
                sloth_iter,
                challenge_count,
                layers,
                partitions,
                circuit,
                groth,
                bench,
                extract,
            );
        }
        _ => panic!(format!("invalid hasher: {}", hasher)),
    }
}
