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

fn do_the_work<H: 'static>(data_size: usize, m: usize, expansion_degree: usize, sloth_iter: usize)
where
    H: Hasher,
{
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let layers = 1;
    info!(FCP_LOG, "data size: {}", prettyb(data_size); "target" => "config");
    info!(FCP_LOG, "m: {}", m; "target" => "config");
    info!(FCP_LOG, "expansion_degree: {}", expansion_degree; "target" => "config");
    info!(FCP_LOG, "sloth: {}", sloth_iter; "target" => "config");
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
    let drgpp = pp.drg_porep_public_params;
    stop_profile();

    let start = Instant::now();
    let mut param_duration = Duration::new(0, 0);

    info!(FCP_LOG, "running replicate");

    start_profile("encod");
    vde::encode(&drgpp.graph, drgpp.sloth_iter, replica_id, data);
    stop_profile();
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

    info!(FCP_LOG, "hasher: {}", hasher; "target" => "config");
    do_the_work::<PedersenHasher>(data_size, m, expansion_degree, sloth_iter);
}
