#[macro_use]
extern crate clap;
#[macro_use]
extern crate slog;

use clap::{App, Arg};
use paired::bls12_381::{Bls12, Fr};
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

use filecoin_proofs::singletons::FCP_LOG;

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

fn do_the_work<AH, BH>(data_size: usize, m: usize, sloth_iter: usize, challenge_count: usize)
where
    AH: Hasher,
    BH: Hasher,
{
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
    let pp = DrgPoRep::<AH, BH, BucketGraph<AH, BH>>::setup(&sp).unwrap();

    let start = Instant::now();
    let mut param_duration = Duration::new(0, 0);

    info!(FCP_LOG, "running replicate");
    let (tau, aux) =
        DrgPoRep::<AH, BH, _>::replicate(&pp, &replica_id.into(), &mut mmapped, None).unwrap();

    let pub_inputs = PublicInputs::<AH::Domain, BH::Domain> {
        replica_id: Some(replica_id.into()),
        challenges,
        tau: Some(tau),
    };

    let priv_inputs = PrivateInputs::<AH, BH> {
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
            DrgPoRep::<AH, BH, _>::prove(&pp, &pub_inputs, &priv_inputs).expect("failed to prove");
        total_proving += start.elapsed();

        let start = Instant::now();
        DrgPoRep::<AH, BH, _>::verify(&pp, &pub_inputs, &proof).expect("failed to verify");
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
            Arg::with_name("alpha-hasher")
                .long("alpha-hasher")
                .help("Which alpha hasher should be used.Available: \"pedersen\", \"sha256\", \"blake2s\" (default \"pedersen\")")
                .default_value("pedersen")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("beta-hasher")
                .long("beta-hasher")
                .help("Which beta hasher should be used.Available: \"pedersen\", \"sha256\", \"blake2s\" (default \"blake2s\")")
                .default_value("blake2s")
                .takes_value(true),
        )
        .get_matches();

    let data_size = value_t!(matches, "size", usize).unwrap() * 1024;
    let m = value_t!(matches, "m", usize).unwrap();
    let sloth_iter = value_t!(matches, "sloth", usize).unwrap();
    let challenge_count = value_t!(matches, "challenges", usize).unwrap();

    let alpha_hasher = value_t!(matches, "alpha-hasher", String).unwrap();
    let beta_hasher = value_t!(matches, "beta-hasher", String).unwrap();
    info!(FCP_LOG, "alpha-hasher: {}", alpha_hasher; "target" => "config");
    info!(FCP_LOG, "beta-hasher: {}", beta_hasher; "target" => "config");

    match (alpha_hasher.as_ref(), beta_hasher.as_ref()) {
        ("blake2s", "blake2s") => {
            do_the_work::<Blake2sHasher, Blake2sHasher>(data_size, m, sloth_iter, challenge_count);
        }
        ("blake2s", "pedersen") => {
            do_the_work::<Blake2sHasher, PedersenHasher>(data_size, m, sloth_iter, challenge_count);
        }
        ("blake2s", "sha256") => {
            do_the_work::<Blake2sHasher, Sha256Hasher>(data_size, m, sloth_iter, challenge_count);
        }
        ("pedersen", "blake2s") => {
            do_the_work::<PedersenHasher, Blake2sHasher>(data_size, m, sloth_iter, challenge_count);
        }
        ("pedersen", "pedersen") => {
            do_the_work::<PedersenHasher, PedersenHasher>(
                data_size,
                m,
                sloth_iter,
                challenge_count,
            );
        }
        ("pedersen", "sha256") => {
            do_the_work::<PedersenHasher, Sha256Hasher>(data_size, m, sloth_iter, challenge_count);
        }
        ("sha256", "blake2s") => {
            do_the_work::<Sha256Hasher, Blake2sHasher>(data_size, m, sloth_iter, challenge_count);
        }
        ("sha256", "pedersen") => {
            do_the_work::<Sha256Hasher, PedersenHasher>(data_size, m, sloth_iter, challenge_count);
        }
        ("sha256", "sha256") => {
            do_the_work::<Sha256Hasher, Sha256Hasher>(data_size, m, sloth_iter, challenge_count);
        }
        _ => panic!(format!(
            "at least one of the hasher arguments is invalid: {}, {}",
            alpha_hasher, beta_hasher
        )),
    }
}
