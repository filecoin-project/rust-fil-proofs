extern crate bellman;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate memmap;
extern crate tempfile;

extern crate storage_proofs;

use clap::{App, Arg};
use pairing::bls12_381::{Bls12, Fr};
use rand::{Rng, SeedableRng, XorShiftRng};
use std::time::{Duration, Instant};

use storage_proofs::drgporep::*;
use storage_proofs::drgraph::*;
use storage_proofs::example_helper::{init_logger, prettyb};
use storage_proofs::fr32::fr_into_bytes;
<<<<<<< HEAD
use storage_proofs::hasher::pedersen::*;
=======
use storage_proofs::hasher::{Blake2sHasher, Hasher, PedersenHasher, Sha256Hasher};
>>>>>>> 2a019ce... feat: add blake2s hasher
use storage_proofs::porep::PoRep;
use storage_proofs::proof::ProofScheme;

use memmap::MmapMut;
use memmap::MmapOptions;
use std::fs::File;
use std::io::Write;

fn file_backed_mmap_from_random_bytes(n: usize) -> MmapMut {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let mut tmpfile: File = tempfile::tempfile().unwrap();

    // FIXME: Don't materialize the data first: just write it to disk.
    for _ in 0..n {
        tmpfile
            .write_all(&fr_into_bytes::<Bls12>(&rng.gen()))
            .unwrap();
    }

    unsafe { MmapOptions::new().map_mut(&tmpfile).unwrap() }
}

fn do_the_work(data_size: usize, m: usize, sloth_iter: usize, challenge_count: usize) {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let challenges = vec![2; challenge_count];
    let lambda = 32;

    info!(target: "config", "data size: {}", prettyb(data_size));
    info!(target: "config", "m: {}", m);
    info!(target: "config", "sloth: {}", sloth_iter);

    info!("generating fake data");

    let nodes = data_size / lambda;

    let replica_id: Fr = rng.gen();

    let mut mmapped = file_backed_mmap_from_random_bytes(nodes);

    let sp = SetupParams {
        lambda,
        drg: DrgParams {
            nodes,
            degree: m,
            expansion_degree: 0,
            seed: new_seed(),
        },
        sloth_iter,
    };

    info!("running setup");
    let pp = DrgPoRep::<PedersenHasher, BucketGraph<_>>::setup(&sp).unwrap();

    let start = Instant::now();
    let mut param_duration = Duration::new(0, 0);

    info!("running replicate");
    let (tau, aux) =
        DrgPoRep::<PedersenHasher, _>::replicate(&pp, &replica_id.into(), &mut mmapped).unwrap();

    let pub_inputs = PublicInputs {
        replica_id: replica_id.into(),
        challenges,
        tau: Some(tau),
    };

    let priv_inputs = PrivateInputs::<PedersenHasher> {
        replica: &mmapped,
        aux: &aux,
    };

    param_duration += start.elapsed();
    let samples: u32 = 30;

    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    let mut proofs = Vec::with_capacity(samples as usize);
    info!("sampling proving & verifying (samples: {})", samples);
    for _ in 0..samples {
        let start = Instant::now();
        let proof = DrgPoRep::<PedersenHasher, _>::prove(&pp, &pub_inputs, &priv_inputs)
            .expect("failed to prove");
        total_proving += start.elapsed();

        let start = Instant::now();
        DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, &proof).expect("failed to verify");
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

    info!(target: "stats", "Average proving time: {:?} seconds", proving_avg);
    info!(target: "stats", "Average verifying time: {:?} seconds", verifying_avg);
    info!(target: "stats", "Replication time: {:?}", param_duration);
    info!(target: "stats", "Average proof size {}", prettyb(avg_proof_size));
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
    info!(target: "config", "hasher: {}", hasher);
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
