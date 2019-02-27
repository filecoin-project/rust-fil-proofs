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
use memmap::MmapMut;
use memmap::MmapOptions;
use pairing::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::fs::File;
use std::io::Write;
use std::time::Instant;

use storage_proofs::drgporep;
use storage_proofs::drgraph::*;
use storage_proofs::example_helper::prettyb;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::{Hasher, PedersenHasher};
use storage_proofs::layered_drgporep::{self, LayerChallenges};
use storage_proofs::proof::ProofScheme;
use storage_proofs::vde;
use storage_proofs::zigzag_drgporep::*;

use filecoin_proofs::FCP_LOG;

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

    info!(FCP_LOG, "data size: {}", prettyb(data_size); "target" => "config");
    info!(FCP_LOG, "m: {}", m; "target" => "config");
    info!(FCP_LOG, "expansion_degree: {}", expansion_degree; "target" => "config");
    info!(FCP_LOG, "sloth: {}", sloth_iter; "target" => "config");
    info!(FCP_LOG, "generating fake data"; "target" => "status");

    let nodes = data_size / 32;

    let mut data = file_backed_mmap_from_random_bytes(nodes);

    let replica_id: H::Domain = rng.gen();

    let sp = layered_drgporep::SetupParams {
        drg: drgporep::DrgParams {
            nodes,
            degree: m,
            expansion_degree,
            seed: new_seed(),
        },
        sloth_iter,
        layer_challenges: LayerChallenges::new_fixed(1, 1),
    };

    info!(FCP_LOG, "running setup");
    start_profile("setup");
    let pp = ZigZagDrgPoRep::<H>::setup(&sp).unwrap();
    stop_profile();

    let start = Instant::now();

    info!(FCP_LOG, "encoding");

    start_profile("encode");
    vde::encode(&pp.graph, pp.sloth_iter, &replica_id, &mut data).unwrap();
    stop_profile();

    let encoding_time = start.elapsed();
    info!(FCP_LOG, "encoding_time: {:?}", encoding_time; "target" => "stats");

    info!(
        FCP_LOG,
        "encoding time/byte: {:?}",
        encoding_time / data_size as u32; "target" => "stats"
    );
    info!(
        FCP_LOG,
        "encoding time/GiB: {:?}",
        (1 << 30) * encoding_time / data_size as u32; "target" => "stats"
    );
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
            Arg::with_name("layers")
                .long("layers")
                .help("How many layers to use")
                .default_value("10")
                .takes_value(true),
        )
        .get_matches();

    let data_size = value_t!(matches, "size", usize).unwrap() * 1024;
    let m = value_t!(matches, "m", usize).unwrap();
    let expansion_degree = value_t!(matches, "exp", usize).unwrap();
    let sloth_iter = value_t!(matches, "sloth", usize).unwrap();

    do_the_work::<PedersenHasher>(data_size, m, expansion_degree, sloth_iter);
}
