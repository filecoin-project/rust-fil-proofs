extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
#[macro_use]
extern crate clap;
#[cfg(feature = "cpu-profile")]
extern crate gperftools;
extern crate memmap;
extern crate tempfile;
#[macro_use]
extern crate slog;

extern crate filecoin_proofs;
extern crate storage_proofs;

use clap::{App, Arg};
#[cfg(feature = "cpu-profile")]
use gperftools::profiler::PROFILER;
use pairing::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::time::{Duration, Instant};

use filecoin_proofs::FCP_LOG;
use storage_proofs::beacon_post::*;
use storage_proofs::drgraph::*;
use storage_proofs::example_helper::prettyb;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::pedersen::PedersenDomain;
use storage_proofs::hasher::PedersenHasher;
use storage_proofs::proof::ProofScheme;
use storage_proofs::{vdf_post, vdf_sloth};

#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn start_profile(stage: &str) {
    PROFILER
        .lock()
        .unwrap()
        .start(format!("./{}.profile", stage))
        .unwrap();
}

#[cfg(not(feature = "cpu-profile"))]
#[inline(always)]
fn start_profile(_stage: &str) {}

#[cfg(feature = "cpu-profile")]
#[inline(always)]
fn stop_profile() {
    PROFILER.lock().unwrap().stop().unwrap();
}

#[cfg(not(feature = "cpu-profile"))]
#[inline(always)]
fn stop_profile() {}

fn do_the_work(
    size: usize,
    vdf: usize,
    challenge_count: usize,
    post_epochs: usize,
    post_periods_count: usize,
    sectors_count: usize,
) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    info!(FCP_LOG, "sector size: {}", prettyb(size); "target" => "config");
    info!(FCP_LOG, "vdf: {}", vdf; "target" => "config");
    info!(FCP_LOG, "challenge_count: {}", challenge_count; "target" => "config");
    info!(FCP_LOG, "post_epochs: {}", post_epochs; "target" => "config");
    info!(FCP_LOG, "post_periods_count: {:?}", post_periods_count; "target" => "config");
    info!(FCP_LOG, "sectors_count: {:?}", sectors_count; "target" => "config");

    info!(FCP_LOG, "generating fake data"; "target" => "status");

    let nodes_size = size / 32;

    let data: Vec<Vec<u8>> = (0..sectors_count)
        .map(|_| {
            (0..nodes_size)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect()
        })
        .collect();

    let graphs: Vec<_> = (0..sectors_count)
        .map(|_| BucketGraph::<PedersenHasher>::new(nodes_size, 5, 0, new_seed()))
        .collect();

    let trees: Vec<_> = graphs
        .iter()
        .zip(data.iter())
        .map(|(graph, data)| graph.merkle_tree(data.as_slice()).unwrap())
        .collect();

    let sp = SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
        vdf_post_setup_params: vdf_post::SetupParams::<PedersenDomain, vdf_sloth::Sloth> {
            challenge_count,
            sector_size: size,
            post_epochs,
            setup_params_vdf: vdf_sloth::SetupParams {
                key: rng.gen(),
                rounds: vdf,
            },
            sectors_count,
        },
        post_periods_count,
    };

    info!(FCP_LOG, "running setup");
    start_profile("setup");
    let pub_params = BeaconPoSt::<PedersenHasher, vdf_sloth::Sloth>::setup(&sp).unwrap();
    stop_profile();

    let pub_inputs = PublicInputs {
        commitments: trees.iter().map(|t| t.root()).collect(),
    };

    let trees_ref: Vec<_> = trees.iter().collect();
    let replicas: Vec<&[u8]> = data.iter().map(|d| &d[..]).collect();

    let priv_inputs = PrivateInputs::<PedersenHasher>::new(&replicas, &trees_ref[..]);

    let mut total_proving = Duration::new(0, 0);
    info!(FCP_LOG, "generating proofs");

    let start = Instant::now();
    start_profile("prove");
    let proof = BeaconPoSt::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();
    stop_profile();

    total_proving += start.elapsed();

    let proving_avg = total_proving;
    let proving_avg =
        f64::from(proving_avg.subsec_nanos()) / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    info!(FCP_LOG, "proving_time: {:?} seconds", proving_avg; "target" => "stats");

    let samples: u32 = 5;
    info!(FCP_LOG, "sampling verifying (samples: {})", samples);
    let mut total_verifying = Duration::new(0, 0);

    start_profile("verify");
    for _ in 0..samples {
        let start = Instant::now();
        let verified = BeaconPoSt::verify(&pub_params, &pub_inputs, &proof).unwrap();

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
    info!(FCP_LOG, "average_verifying_time: {:?} seconds", verifying_avg; "target" => "stats");
}

fn main() {
    let matches = App::new(stringify!("DrgPoRep Vanilla Bench"))
        .version("1.0")
        .arg(
            Arg::with_name("size")
                .required(true)
                .long("size")
                .help("The data size of a sector in KB")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("vdf")
                .help("The number of sloth iterations")
                .long("vdf")
                .default_value("10")
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
            Arg::with_name("post-epochs")
                .long("post-epochs")
                .help("How many epochs should the PoSt run for")
                .default_value("10")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("post-periods-count")
                .long("post-periods-count")
                .help("How many PoSt periods should there be")
                .default_value("10")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sectors")
                .long("sectors")
                .help("How many sector are being proven")
                .default_value("5")
                .takes_value(true),
        )
        .get_matches();

    let size = value_t!(matches, "size", usize).unwrap() * 1024;
    let vdf = value_t!(matches, "vdf", usize).unwrap();
    let challenge_count = value_t!(matches, "challenges", usize).unwrap();
    let post_epochs = value_t!(matches, "post-epochs", usize).unwrap();
    let post_periods_count = value_t!(matches, "post-periods-count", usize).unwrap();
    let sectors_count = value_t!(matches, "sectors", usize).unwrap();

    do_the_work(
        size,
        vdf,
        challenge_count,
        post_epochs,
        post_periods_count,
        sectors_count,
    );
}
