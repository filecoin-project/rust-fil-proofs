extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;
extern crate env_logger;
#[cfg(feature = "profile")]
extern crate gperftools;

extern crate storage_proofs;

use clap::{App, Arg};
use pairing::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::time::{Duration, Instant};

#[cfg(feature = "profile")]
use gperftools::profiler::PROFILER;

use storage_proofs::drgporep;
use storage_proofs::drgraph::*;
use storage_proofs::example_helper::{init_logger, prettyb};
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::{Blake2sHasher, Hasher, PedersenHasher, Sha256Hasher};
use storage_proofs::layered_drgporep;
use storage_proofs::porep::PoRep;
use storage_proofs::proof::ProofScheme;
use storage_proofs::zigzag_drgporep::*;

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

fn do_the_work<H: 'static>(
    data_size: usize,
    m: usize,
    expansion_degree: usize,
    sloth_iter: usize,
    challenge_count: usize,
    layers: usize,
    partitions: usize,
) where
    H: Hasher,
{
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let lambda = 32;

    info!(target: "config", "data size: {}", prettyb(data_size));
    info!(target: "config", "m: {}", m);
    info!(target: "config", "expansion_degree: {}", expansion_degree);
    info!(target: "config", "sloth: {}", sloth_iter);
    info!(target: "config", "challenge_count: {}", challenge_count);
    info!(target: "config", "layers: {}", layers);
    info!(target: "partitions", "partitions: {}", partitions);

    info!("generating fake data");

    let nodes = data_size / lambda;

    let replica_id: H::Domain = rng.gen();
    let data: Vec<u8> = (0..nodes)
        .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
        .collect();
    let mut data_copy = data.clone();

    let sp = layered_drgporep::SetupParams {
        drg_porep_setup_params: drgporep::SetupParams {
            lambda,
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

    info!("running setup");
    start_profile("setup");
    let pp = ZigZagDrgPoRep::<H>::setup(&sp).unwrap();
    stop_profile();

    let start = Instant::now();
    let mut param_duration = Duration::new(0, 0);

    info!("running replicate");

    start_profile("replicate");
    let (tau, aux) =
        ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, data_copy.as_mut_slice()).unwrap();
    stop_profile();
    let pub_inputs = layered_drgporep::PublicInputs::<H::Domain> {
        replica_id,
        challenge_count,
        tau: Some(tau.simplify().into()),
        comm_r_star: tau.comm_r_star,
        k: Some(0),
    };

    let priv_inputs = layered_drgporep::PrivateInputs {
        replica: data.as_slice(),
        aux,
        tau: tau.layer_taus,
    };

    param_duration += start.elapsed();
    let samples: u32 = 1;

    info!(target: "stats", "Replication time: {:?}", param_duration);

    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    let mut proofs = Vec::with_capacity(samples as usize);
    info!("sampling proving & verifying (samples: {})", samples);
    for _ in 0..samples {
        let start = Instant::now();
        start_profile("prove");
        let all_partition_proofs =
            ZigZagDrgPoRep::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, partitions)
                .expect("failed to prove");
        stop_profile();
        total_proving += start.elapsed();

        let start = Instant::now();
        start_profile("verify");
        let verified =
            ZigZagDrgPoRep::<H>::verify_all_partitions(&pp, &pub_inputs, &all_partition_proofs)
                .expect("failed during verification");
        if !verified {
            info!(target: "results", "Verification failed.");
        };
        stop_profile();
        total_verifying += start.elapsed();
        proofs.push(all_partition_proofs);
    }

    // -- print statistics

    //    let serialized_proofs = proofs.iter().fold(Vec::new(), |mut acc, p| {
    //        acc.extend(p.serialize());
    //        acc
    //    });
    //    let avg_proof_size = serialized_proofs.len() / samples as usize;
    //
    let proving_avg = total_proving / samples;
    let proving_avg =
        f64::from(proving_avg.subsec_nanos()) / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / samples;
    let verifying_avg = f64::from(verifying_avg.subsec_nanos()) / 1_000_000_000f64
        + (verifying_avg.as_secs() as f64);

    info!(target: "stats", "Average proving time: {:?} seconds", proving_avg);
    //info!(target: "stats", "Average proof size {}", prettyb(avg_proof_size));
    info!(target: "stats", "Average verifying time: {:?} seconds", verifying_avg);
}

fn main() {
    init_logger();

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
                .default_value("6")
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
                .help("The number of sloth iterations, defaults to 1")
                .long("sloth")
                .default_value("1")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("challenges")
                .long("challenges")
                .help("How many challenges to execute, defaults to 1")
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
                .help("How many layers to use, defaults to 1")
                .default_value("6")
                .takes_value(true),
        )
       .arg(
            Arg::with_name("partitions")
                .long("partitions")
                .help("How many circuit partitions to use, defaults to 1")
                .default_value("1")
                .takes_value(true),
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
    info!(target: "config", "hasher: {}", hasher);
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
            );
        }
        _ => panic!(format!("invalid hasher: {}", hasher)),
    }
}
