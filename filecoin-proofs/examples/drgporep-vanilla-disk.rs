extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
#[macro_use]
extern crate clap;
extern crate memmap;
extern crate tempfile;

#[macro_use]
extern crate slog;

extern crate filecoin_proofs;
extern crate storage_proofs;

use clap::{App, Arg};
use pairing::bls12_381::{Bls12, Fr};
use rand::{Rng, SeedableRng, XorShiftRng};
use std::time::{Duration, Instant};

use storage_proofs::drgporep::*;
use storage_proofs::drgraph::*;
use storage_proofs::example_helper::prettyb;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::{Blake2sHasher, Hasher, PedersenHasher, Sha256Hasher};
use storage_proofs::porep::PoRep;
use storage_proofs::proof::ProofScheme;

use memmap::MmapMut;
use memmap::MmapOptions;
use std::fs::File;
use std::io::Write;

use filecoin_proofs::FCP_LOG;

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

fn do_the_work<H: Hasher>(data_size: usize, m: usize, sloth_iter: usize, challenge_count: usize) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let challenges = vec![2; challenge_count];

    info!(FCP_LOG, "data_size:  {}", prettyb(data_size); "target" => "config");
    info!(FCP_LOG, "challenge_count: {}", challenge_count; "target" => "config");
    info!(FCP_LOG, "m: {}", m; "target" => "config");
    info!(FCP_LOG, "sloth: {}", sloth_iter; "target" => "config");

    info!(FCP_LOG, "generating fake data");

    let nodes = data_size / 32;

    let replica_id: Fr = rng.gen();

    let mut mmapped = file_backed_mmap_from_random_bytes(nodes);

    let sp = SetupParams {
        drg: DrgParams {
            nodes,
            degree: m,
            expansion_degree: 0,
            seed: new_seed(),
        },
        sloth_iter,
        private: true,
        challenges_count: challenge_count,
    };

    info!(FCP_LOG, "running setup");
    let pp = DrgPoRep::<H, BucketGraph<_>>::setup(&sp).unwrap();

    let start = Instant::now();
    let mut param_duration = Duration::new(0, 0);

    info!(FCP_LOG, "running replicate");
    let (tau, aux) =
        DrgPoRep::<H, _>::replicate(&pp, &replica_id.into(), &mut mmapped, None).unwrap();

    let pub_inputs = PublicInputs::<H::Domain> {
        replica_id: Some(replica_id.into()),
        challenges,
        tau: Some(tau),
    };

    let priv_inputs = PrivateInputs::<H> {
        tree_d: &aux.tree_d,
        tree_r: &aux.tree_r,
    };

    param_duration += start.elapsed();
    let samples: u32 = 30;

    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    let mut proofs = Vec::with_capacity(samples as usize);
    info!(
        FCP_LOG,
        "sampling proving & verifying (samples: {})", samples
    );
    for _ in 0..samples {
        let start = Instant::now();
        let proof =
            DrgPoRep::<H, _>::prove(&pp, &pub_inputs, &priv_inputs).expect("failed to prove");
        total_proving += start.elapsed();

        let start = Instant::now();
        DrgPoRep::<H, _>::verify(&pp, &pub_inputs, &proof).expect("failed to verify");
        total_verifying += start.elapsed();
        proofs.push(proof);
    }

    // -- print statistics

    let serialized_proofs = proofs.iter().fold(Vec::new(), |mut acc, p| {
        acc.extend(p.serialize());
        acc
    });
    let avg_proof_size = serialized_proofs.len() / samples as usize;

    let proving_avg = total_proving / samples;
    let proving_avg =
        f64::from(proving_avg.subsec_nanos()) / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / samples;
    let verifying_avg = f64::from(verifying_avg.subsec_nanos()) / 1_000_000_000f64
        + (verifying_avg.as_secs() as f64);

    info!(FCP_LOG, "avg_proving_time: {:?} seconds", proving_avg; "target" => "stats");
    info!(FCP_LOG, "avg_verifying_time: {:?} seconds", verifying_avg; "target" => "stats");
    info!(FCP_LOG, "replication_time={:?}", param_duration; "target" => "stats");
    info!(FCP_LOG, "avg_proof_size: {}", prettyb(avg_proof_size); "target" => "stats");
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
                .default_value("6")
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
        .get_matches();

    let data_size = value_t!(matches, "size", usize).unwrap() * 1024;
    let m = value_t!(matches, "m", usize).unwrap();
    let sloth_iter = value_t!(matches, "sloth", usize).unwrap();
    let challenge_count = value_t!(matches, "challenges", usize).unwrap();

    let hasher = value_t!(matches, "hasher", String).unwrap();
    info!(FCP_LOG, "hasher: {}", hasher; "target" => "config");
    match hasher.as_ref() {
        "pedersen" => {
            do_the_work::<PedersenHasher>(data_size, m, sloth_iter, challenge_count);
        }
        "sha256" => {
            do_the_work::<Sha256Hasher>(data_size, m, sloth_iter, challenge_count);
        }
        "blake2s" => {
            do_the_work::<Blake2sHasher>(data_size, m, sloth_iter, challenge_count);
        }
        _ => panic!(format!("invalid hasher: {}", hasher)),
    }
}
