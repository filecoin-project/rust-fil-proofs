use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom};
use std::mem::size_of;
use std::path::Path;
use std::process::Command;
use std::str::{self, FromStr};
use std::sync::mpsc::{channel, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ReadBytesExt};
use clap::{App, AppSettings, Arg, ArgGroup, SubCommand};
use filecoin_proofs::constants::*;
use filecoin_proofs::parameters::{
    setup_params, window_post_public_params, winning_post_public_params,
};
use filecoin_proofs::types::{
    PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, PoStType, SectorSize,
};
use filecoin_proofs::with_shape;
use groupy::{CurveAffine, EncodedPoint};
use log::{error, info, warn};
use paired::bls12_381::{G1Affine, G1Uncompressed, G2Affine, G2Uncompressed};
use phase2::small::{read_small_params_from_large_file, MPCSmall, Streamer};
use phase2::MPCParameters;
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use simplelog::{self, CombinedLogger, LevelFilter, TermLogger, TerminalMode, WriteLogger};
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::hasher::Sha256Hasher;
use storage_proofs::merkle::MerkleTreeTrait;
use storage_proofs::porep::stacked::{StackedCircuit, StackedCompound, StackedDrg};
use storage_proofs::post::fallback::{FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound};

const CHUNK_SIZE: usize = 10_000;

// Non-raw sizes.
const G1_SIZE: u64 = size_of::<G1Uncompressed>() as u64; // 96
const G2_SIZE: u64 = size_of::<G2Uncompressed>() as u64; // 192

const PUBKEY_SIZE: u64 = 3 * G1_SIZE + G2_SIZE + 64; // 544

fn get_head_commit() -> String {
    let output = Command::new("git")
        .args(&["rev-parse", "--short=7", "HEAD"])
        .output()
        .expect("failed to execute child process: `git rev-parse --short=7 HEAD`");

    str::from_utf8(&output.stdout)
        .expect("`git` child process outputed invalid Utf8 bytes")
        .trim()
        .to_lowercase()
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Proof {
    Sdr,
    Winning,
    Window,
}

impl Proof {
    fn pretty_print(&self) -> &str {
        match self {
            Proof::Sdr => "SDR",
            Proof::Winning => "Winning",
            Proof::Window => "Window",
        }
    }

    fn lowercase(&self) -> &str {
        match self {
            Proof::Sdr => "sdr",
            Proof::Winning => "winning",
            Proof::Window => "window",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Hasher {
    Poseidon,
    // ShaPedersen,
}

impl Hasher {
    // Used for printing during logging. Implementing Debug and Display is less clear than having
    // methods `.pretty_print()` and `.lowercase()` which differentiate between printing for logging
    // v.s. printing for filenames.
    fn pretty_print(&self) -> &str {
        match self {
            Hasher::Poseidon => "Poseidon",
            // Hasher::ShaPedersen => "SHA-Pederson",
        }
    }

    // Used for constructing param filenames.
    fn lowercase(&self) -> &str {
        match self {
            Hasher::Poseidon => "poseidon",
            // Hasher::ShaPedersen => "shapederson",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum Sector {
    SectorSize2KiB,
    SectorSize4KiB,
    SectorSize16KiB,
    SectorSize32KiB,
    SectorSize8MiB,
    SectorSize16MiB,
    SectorSize512MiB,
    SectorSize1GiB,
    SectorSize32GiB,
    SectorSize64GiB,
}

impl Sector {
    fn as_u64(self) -> u64 {
        match self {
            Sector::SectorSize2KiB => SECTOR_SIZE_2_KIB,
            Sector::SectorSize4KiB => SECTOR_SIZE_4_KIB,
            Sector::SectorSize16KiB => SECTOR_SIZE_16_KIB,
            Sector::SectorSize32KiB => SECTOR_SIZE_32_KIB,
            Sector::SectorSize8MiB => SECTOR_SIZE_8_MIB,
            Sector::SectorSize16MiB => SECTOR_SIZE_16_MIB,
            Sector::SectorSize512MiB => SECTOR_SIZE_512_MIB,
            Sector::SectorSize1GiB => SECTOR_SIZE_1_GIB,
            Sector::SectorSize32GiB => SECTOR_SIZE_32_GIB,
            Sector::SectorSize64GiB => SECTOR_SIZE_64_GIB,
        }
    }

    fn lowercase(&self) -> &str {
        match self {
            Sector::SectorSize2KiB => "2kib",
            Sector::SectorSize4KiB => "4kib",
            Sector::SectorSize16KiB => "16kib",
            Sector::SectorSize32KiB => "32kib",
            Sector::SectorSize8MiB => "8mib",
            Sector::SectorSize16MiB => "16mib",
            Sector::SectorSize512MiB => "512mib",
            Sector::SectorSize1GiB => "1gib",
            Sector::SectorSize32GiB => "32gib",
            Sector::SectorSize64GiB => "64gib",
        }
    }

    fn pretty_print(&self) -> &str {
        match self {
            Sector::SectorSize2KiB => "2KiB",
            Sector::SectorSize4KiB => "4KiB",
            Sector::SectorSize16KiB => "16KiB",
            Sector::SectorSize32KiB => "32KiB",
            Sector::SectorSize8MiB => "8MiB",
            Sector::SectorSize16MiB => "16MiB",
            Sector::SectorSize512MiB => "512MiB",
            Sector::SectorSize1GiB => "1GiB",
            Sector::SectorSize32GiB => "32GiB",
            Sector::SectorSize64GiB => "64GiB",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ParamSize {
    Large,
    Small,
}

impl ParamSize {
    fn pretty_print(&self) -> &str {
        match self {
            ParamSize::Large => "Large",
            ParamSize::Small => "Small",
        }
    }

    fn lowercase(&self) -> &str {
        match self {
            ParamSize::Large => "large",
            ParamSize::Small => "small",
        }
    }

    fn is_small(self) -> bool {
        self == ParamSize::Small
    }

    fn is_large(self) -> bool {
        self == ParamSize::Large
    }
}

fn params_filename(
    proof: Proof,
    hasher: Hasher,
    sector_size: Sector,
    head: &str,
    param_number: usize,
    param_size: ParamSize,
    raw: bool,
) -> String {
    format!(
        "{proof}_{hasher}_{sector}_{head}_{number}_{size}{maybe_fmt}",
        proof = proof.lowercase(),
        hasher = hasher.lowercase(),
        sector = sector_size.lowercase(),
        head = head,
        number = param_number,
        size = param_size.lowercase(),
        maybe_fmt = if raw { "_raw" } else { "" },
    )
}

// Parses a phase2 parameters filename into the tuple:
// (proof, hasher, sector-size, head, param-number, param-size).
fn parse_params_filename(path: &str) -> (Proof, Hasher, Sector, String, usize, ParamSize, bool) {
    // Remove directories from the path.
    let filename = path.rsplitn(2, '/').next().unwrap();
    let split: Vec<&str> = filename.split('_').collect();

    let proof = match split[0] {
        "sdr" => Proof::Sdr,
        "winning" => Proof::Winning,
        "window" => Proof::Window,
        other => panic!("invalid proof name in params filename: {}", other),
    };

    let hasher = match split[1] {
        "poseidon" => Hasher::Poseidon,
        // "shapedersen" => Hasher::ShaPedersen,
        other => panic!("invalid hasher name in params filename: {}", other),
    };

    let sector_size = match split[2] {
        "2kib" => Sector::SectorSize2KiB,
        "4kib" => Sector::SectorSize4KiB,
        "16kib" => Sector::SectorSize16KiB,
        "32kib" => Sector::SectorSize32KiB,
        "8mib" => Sector::SectorSize8MiB,
        "16mib" => Sector::SectorSize16MiB,
        "512mib" => Sector::SectorSize512MiB,
        "1gib" => Sector::SectorSize1GiB,
        "32gib" => Sector::SectorSize32GiB,
        "64gib" => Sector::SectorSize64GiB,
        other => panic!("invalid sector-size in params filename: {}", other),
    };

    let head = split[3].to_string();

    let param_number = usize::from_str(split[4])
        .unwrap_or_else(|_| panic!("invalid param number in params filename: {}", split[4]));

    let param_size = match split[5] {
        "large" => ParamSize::Large,
        "small" => ParamSize::Small,
        other => panic!("invalid param-size in params filename: {}", other),
    };

    let raw_fmt = split.get(6) == Some(&"raw");

    (
        proof,
        hasher,
        sector_size,
        head,
        param_number,
        param_size,
        raw_fmt,
    )
}

fn blank_sdr_poseidon_circuit<Tree: MerkleTreeTrait>(
    sector_size: u64,
) -> StackedCircuit<'static, Tree, Sha256Hasher> {
    let n_partitions = *POREP_PARTITIONS.read().unwrap().get(&sector_size).unwrap();

    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(n_partitions),
        porep_id: [0; 32],
    };

    let setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
            porep_config.porep_id,
        )
        .unwrap(),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let public_params = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
        StackedDrg<Tree, Sha256Hasher>,
        _,
    >>::setup(&setup_params)
    .unwrap();

    <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
        StackedDrg<Tree, Sha256Hasher>,
        _,
    >>::blank_circuit(&public_params.vanilla_params)
}

/*
fn blank_porep_sha_pedersen_circuit(
    sector_size: u64,
) -> StackedCircuit<'static, PedersenHasher, Sha256Hasher> {
    let	n_partitions = *POREP_PARTITIONS.read().unwrap().get(&sector_size).unwrap();

    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(n_partitions),
    };

    let setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )
        .unwrap(),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let public_params =
        <StackedCompound<PedersenHasher, Sha256Hasher> as CompoundProof<_, StackedDrg<PedersenHasher, Sha256Hasher>, _>>::setup(
            &setup_params,
        )
        .unwrap();

    <StackedCompound<PedersenHasher, Sha256Hasher> as CompoundProof<
        _,
        StackedDrg<PedersenHasher, Sha256Hasher>,
        _,
    >>::blank_circuit(&public_params.vanilla_params)
}
*/

fn blank_winning_post_poseidon_circuit<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
) -> FallbackPoStCircuit<Tree> {
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        sector_count: WINNING_POST_SECTOR_COUNT,
        typ: PoStType::Winning,
        priority: false,
    };

    let public_params = winning_post_public_params::<Tree>(&post_config).unwrap();

    <FallbackPoStCompound<Tree> as CompoundProof<
        FallbackPoSt<Tree>,
        FallbackPoStCircuit<Tree>,
    >>::blank_circuit(&public_params)
}

fn blank_window_post_poseidon_circuit<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
) -> FallbackPoStCircuit<Tree> {
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        sector_count: *WINDOW_POST_SECTOR_COUNT
            .read()
            .unwrap()
            .get(&sector_size)
            .unwrap(),
        typ: PoStType::Window,
        priority: false,
    };

    let public_params = window_post_public_params::<Tree>(&post_config).unwrap();

    <FallbackPoStCompound<Tree> as CompoundProof<
        FallbackPoSt<Tree>,
        FallbackPoStCircuit<Tree>,
    >>::blank_circuit(&public_params)
}

/// Creates the first phase2 parameters for a circuit and writes them to a file.
fn create_initial_params<Tree: 'static + MerkleTreeTrait>(
    proof: Proof,
    hasher: Hasher,
    sector_size: Sector,
) {
    let head = get_head_commit();

    info!(
        "creating initial params for circuit: {}-{}-{}-{}",
        proof.pretty_print(),
        hasher.pretty_print(),
        sector_size.pretty_print(),
        head,
    );

    let start_total = Instant::now();
    let dt_create_circuit: u64;
    let dt_create_params: u64;

    let params = match (proof, hasher) {
        (Proof::Sdr, Hasher::Poseidon) => {
            let start = Instant::now();
            let circuit = blank_sdr_poseidon_circuit::<Tree>(sector_size.as_u64());
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = MPCParameters::new(circuit).unwrap();
            dt_create_params = start.elapsed().as_secs();
            params
        }
        (Proof::Winning, Hasher::Poseidon) => {
            let start = Instant::now();
            let circuit = blank_winning_post_poseidon_circuit::<Tree>(sector_size.as_u64());
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = MPCParameters::new(circuit).unwrap();
            dt_create_params = start.elapsed().as_secs();
            params
        }
        (Proof::Window, Hasher::Poseidon) => {
            let start = Instant::now();
            let circuit = blank_window_post_poseidon_circuit::<Tree>(sector_size.as_u64());
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = MPCParameters::new(circuit).unwrap();
            dt_create_params = start.elapsed().as_secs();
            params
        }
    };

    info!(
        "successfully created initial params for circuit, dt_create_circuit={}s, dt_create_params={}s",
        dt_create_circuit,
        dt_create_params
    );

    let large_path = params_filename(
        proof,
        hasher,
        sector_size,
        &head,
        0,
        ParamSize::Large,
        false,
    );
    let small_path = params_filename(proof, hasher, sector_size, &head, 0, ParamSize::Small, true);

    {
        info!("writing large initial params to file: {}", large_path);
        let file = File::create(&large_path).unwrap();
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        params.write(&mut writer).unwrap();
        info!("finished writing large params to file");
    }

    {
        info!("writing small initial params to file: {}", small_path);
        let file = File::create(&small_path).unwrap();
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        params.write_small(&mut writer).unwrap();
        info!("finished writing small params to file");
    }

    info!(
        "successfully created and wrote initial params for circuit: {}-{}-{}-{}, dt_total={}s",
        proof.pretty_print(),
        hasher.pretty_print(),
        sector_size.pretty_print(),
        head,
        start_total.elapsed().as_secs()
    );
}

// Encodes a contribution into a hex string (lowercase, no leading "0x").
fn hex_string(contrib: &[u8; 64]) -> String {
    hex::encode(&contrib[..])
}

fn get_mixed_entropy() -> [u8; 32] {
    use dialoguer::theme::ColorfulTheme;
    use dialoguer::Password;

    let mut os_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut os_entropy);

    let user_input = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Please randomly press your keyboard (press Return/Enter when finished)")
        .interact()
        .unwrap();

    let mut blake2b = blake2b_simd::Params::default();
    blake2b.hash_length(32);
    let digest = blake2b.hash(user_input.as_bytes());
    let user_entropy = digest.as_bytes();

    let mut seed = [0u8; 32];
    for i in 0..32 {
        seed[i] = os_entropy[i] ^ user_entropy[i];
    }
    seed
}

/// Contributes entropy to the current phase2 parameters for a circuit, then writes the updated
/// parameters to a new file.
fn contribute_to_params_streaming(path_before: &str, write_raw: bool) {
    let (proof, hasher, sector_size, head, prev_param_number, param_size, read_raw) =
        parse_params_filename(path_before);

    let param_number = prev_param_number + 1;

    info!(
        "contributing to params for circuit: {}-{}-{}-{}-{} {}->{}",
        proof.pretty_print(),
        hasher.pretty_print(),
        sector_size.pretty_print(),
        head,
        param_size.pretty_print(),
        prev_param_number,
        param_number
    );

    // Get OS entropy prior to deserialization the previous participant's params.
    let seed = get_mixed_entropy();
    let mut rng = ChaChaRng::from_seed(seed);

    // Default to small params for first participant.
    let path_after = params_filename(
        proof,
        hasher,
        sector_size,
        &head,
        param_number,
        ParamSize::Small,
        write_raw,
    );

    let start_total = Instant::now();

    info!("making contribution");
    let start_contrib = Instant::now();

    info!(
        "making streamer from small 'before' params: {}",
        path_before
    );

    let mut streamer = if param_size.is_large() {
        Streamer::new_from_large_file(path_before, read_raw, write_raw).unwrap_or_else(|e| {
            panic!(
                "failed to make streamer from large `{}`: {}",
                path_before, e
            );
        })
    } else {
        Streamer::new(path_before, read_raw, write_raw).unwrap_or_else(|e| {
            panic!(
                "failed to make streamer from small `{}`: {}",
                path_before, e
            );
        })
    };

    info!("writing small 'after' params to file: {}", path_after);
    let file_after = File::create(&path_after).unwrap_or_else(|e| {
        panic!(
            "failed to create 'after' params file `{}`: {}",
            path_after, e
        );
    });

    let contrib = streamer
        .contribute(&mut rng, file_after, CHUNK_SIZE)
        .unwrap_or_else(|e| panic!("failed to make streaming contribution: {}", e));

    let contrib_str = hex_string(&contrib);
    info!(
        "successfully made contribution: {}, dt_contribute={}s",
        contrib_str,
        start_contrib.elapsed().as_secs()
    );

    let contrib_path = format!("{}.contrib", path_after);
    info!("writing contribution hash to file: {}", contrib_path);
    fs::write(&contrib_path, contrib_str).unwrap_or_else(|e| {
        panic!(
            "failed to write contribution to file `{}`: {}",
            contrib_path, e
        );
    });

    info!(
        "successfully made contribution, dt_total={}s",
        start_total.elapsed().as_secs()
    );
}

fn convert_small(path_before: &str) {
    let (proof, hasher, sector_size, head, param_number, param_size, read_raw) =
        parse_params_filename(path_before);

    // TODO: change this if we update the large MPC params (and G2Affine) to support the raw serialization format.
    assert!(
        param_size.is_small(),
        "converting large params to raw format is not currently supported"
    );

    let write_raw = !read_raw;

    info!(
        "converting params {to_from} raw format for circuit: {proof}-{hasher}-{sector_size}-{head}-{num} {param_size}",
        to_from = if write_raw { "to" } else { "from" },
        proof = proof.pretty_print(),
        hasher = hasher.pretty_print(),
        sector_size = sector_size.pretty_print(),
        head = head,
        num = param_number,
        param_size = param_size.pretty_print(),
    );

    // Default to small params for first participant.
    let path_after = params_filename(
        proof,
        hasher,
        sector_size,
        &head,
        param_number,
        ParamSize::Small,
        write_raw,
    );

    let start_total = Instant::now();

    info!("converting");

    info!(
        "making streamer from small {} params: {}",
        if read_raw { "raw" } else { "non-raw" },
        path_before
    );

    let mut streamer = if param_size.is_large() {
        panic!("cannot convert large param format");
    } else {
        Streamer::new(path_before, read_raw, write_raw).unwrap_or_else(|e| {
            panic!(
                "failed to make streamer from small `{}`: {}",
                path_before, e
            );
        })
    };

    info!(
        "streamer is writing {} formatted params to file: {}",
        if write_raw { "raw" } else { "non-raw" },
        path_after
    );
    let file_after = File::create(&path_after).unwrap_or_else(|e| {
        panic!(
            "failed to create 'after' params file `{}`: {}",
            path_after, e
        );
    });

    streamer
        .process(file_after, CHUNK_SIZE)
        .expect("failed to convert");

    info!(
        "successfully converted, dt_total={}s",
        start_total.elapsed().as_secs()
    );
}

/// Contributes entropy to the current phase2 parameters for a circuit, then writes the updated
/// parameters to a new file.
fn contribute_to_params(path_before: &str) {
    let (proof, hasher, sector_size, head, prev_param_number, param_size, read_raw) =
        parse_params_filename(path_before);

    let param_number = prev_param_number + 1;

    info!(
        "contributing to params for circuit: {}-{}-{}-{}-{} {}->{}",
        proof.pretty_print(),
        hasher.pretty_print(),
        sector_size.pretty_print(),
        head,
        param_size.pretty_print(),
        prev_param_number,
        param_number
    );

    if param_size.is_large() {
        info!("large param file found, contributing as small");
    }

    // Get OS entropy prior to deserialization the previous participant's params.
    let seed = get_mixed_entropy();
    let mut rng = ChaChaRng::from_seed(seed);

    /*
    let path_after =
        params_filename(proof, hasher, sector_size, &head, param_number, param_size);
    */
    // Default to small params for first participant.
    let path_after = params_filename(
        proof,
        hasher,
        sector_size,
        &head,
        param_number,
        ParamSize::Small,
        false,
    );

    let start_total = Instant::now();
    let start_read = Instant::now();

    let mut small_params = if param_size.is_large() {
        info!("reading large 'before' params as small: {}", path_before);
        read_small_params_from_large_file(&path_before).unwrap_or_else(|e| {
            panic!(
                "failed to read large param file `{}` as small: {}",
                path_before, e
            );
        })
    } else {
        info!("reading small 'before' params as small: {}", path_before);
        let file_before = File::open(path_before).unwrap();
        let mut reader = BufReader::with_capacity(1024 * 1024, file_before);
        MPCSmall::read(&mut reader, read_raw).unwrap_or_else(|e| {
            panic!(
                "failed to read small param file `{}` as small: {}",
                path_before, e
            );
        })
    };
    info!(
        "successfully read 'before' params, dt_read={}s",
        start_read.elapsed().as_secs()
    );

    info!("making contribution");
    let start_contrib = Instant::now();
    let contrib = small_params.contribute(&mut rng);
    let contrib_str = hex_string(&contrib);
    info!(
        "successfully made contribution: {}, dt_contribute={}s",
        contrib_str,
        start_contrib.elapsed().as_secs()
    );

    info!("writing small 'after' params to file: {}", path_after);
    let file_after = File::create(&path_after).unwrap_or_else(|e| {
        panic!(
            "failed to create 'after' params file `{}`: {}",
            path_after, e
        );
    });
    let mut writer = BufWriter::with_capacity(1024 * 1024, file_after);
    small_params.write(&mut writer).unwrap();

    let contrib_path = format!("{}.contrib", path_after);
    info!("writing contribution hash to file: {}", contrib_path);
    fs::write(&contrib_path, contrib_str).unwrap_or_else(|e| {
        panic!(
            "failed to write contribution to file `{}`: {}",
            contrib_path, e
        );
    });

    info!(
        "successfully made contribution, dt_total={}s",
        start_total.elapsed().as_secs()
    );

    /*
    info!("reading 'before' params from disk: {}", path_before);
    let file_before = File::open(path_before).unwrap();
    let mut reader = BufReader::with_capacity(1024 * 1024, file_before);
    let start_read = Instant::now();

    let contrib_str = if param_size.is_large() {
        let mut large_params = MPCParameters::read(&mut reader, true).unwrap();
        info!(
            "successfully read 'before' params from disk, dt_read={}s",
            start_read.elapsed().as_secs()
        );

        info!("making contribution");
        let start_contrib = Instant::now();
        let contrib = large_params.contribute(&mut rng);
        let contrib_str = hex_string(&contrib);
        info!(
            "successfully made contribution: {}, dt_contribute={}s",
            contrib_str,
            start_contrib.elapsed().as_secs()
        );

        info!("writing 'after' params to file: {}", path_after);
        let file_after = File::create(&path_after).unwrap();
        let mut writer = BufWriter::with_capacity(1024 * 1024, file_after);
        large_params.write(&mut writer).unwrap();

        contrib_str
    } else {
        let mut small_params = MPCSmall::read(&mut reader).unwrap();
        info!(
            "successfully read 'before' params from disk, dt_read={}s",
            start_read.elapsed().as_secs()
        );

        info!("making contribution");
        let start_contrib = Instant::now();
        let contrib = small_params.contribute(&mut rng);
        let contrib_str = hex_string(&contrib);
        info!(
            "successfully made contribution: {}, dt_contribute={}s",
            contrib_str,
            start_contrib.elapsed().as_secs()
        );

        info!("writing 'after' params to file: {}", path_after);
        let file_after = File::create(&path_after).unwrap();
        let mut writer = BufWriter::with_capacity(1024 * 1024, file_after);
        small_params.write(&mut writer).unwrap();

        contrib_str
    };

    let contrib_path = format!("{}.contrib", path_after);
    info!("writing contribution hash to file: {}", contrib_path);
    fs::write(&contrib_path, contrib_str).unwrap_or_else(|e| {
        panic!(
            "failed to write contribution hash to file `{}`: {}",
            contrib_path, e
        );
    });

    info!(
        "successfully made contribution, dt_total={}s",
        start_total.elapsed().as_secs()
    );
    */
}

fn verify_contribution(path_before: &str, path_after: &str, participant_contrib: [u8; 64]) {
    #[allow(clippy::large_enum_variant)]
    enum Message {
        Done(MPCSmall),
        Error(io::Error),
    }

    let start_total = Instant::now();

    info!(
        "verifying contribution:\n    before: {}\n    after: {}\n    contrib: {}",
        path_before,
        path_after,
        hex_string(&participant_contrib)
    );

    let (before_tx, before_rx) = channel::<Message>();
    let (after_tx, after_rx) = channel::<Message>();

    let path_before = path_before.to_string();
    let path_after = path_after.to_string();

    let before_thread: JoinHandle<()> = thread::spawn(move || {
        let start_read = Instant::now();
        let is_large = path_before.contains("large");
        let is_raw = path_before.ends_with("raw");

        if !is_raw {
            warn!("using non-raw 'before' params");
        }

        let read_res: io::Result<MPCSmall> = if is_large {
            info!(
                "reading large 'before' params as `MPCSmall`: {}",
                path_before
            );
            read_small_params_from_large_file(&path_before)
        } else {
            info!(
                "reading small 'before' params as `MPCSmall`: {}",
                path_before
            );
            File::open(&path_before).and_then(|file| {
                let mut reader = BufReader::with_capacity(1024 * 1024, file);
                MPCSmall::read(&mut reader, is_raw)
            })
        };

        match read_res {
            Ok(params) => {
                let dt_read = start_read.elapsed().as_secs();
                info!("successfully read 'before' params, dt_read={}s", dt_read);
                before_tx.send(Message::Done(params)).unwrap();
            }
            Err(e) => {
                error!("failed to read 'before' params: {}", e);
                before_tx.send(Message::Error(e)).unwrap();
            }
        };
    });

    let after_thread: JoinHandle<()> = thread::spawn(move || {
        let start_read = Instant::now();
        let is_large = path_after.contains("large");
        let is_raw = path_after.ends_with("raw");

        if !is_raw {
            warn!("using non-raw 'after' params");
        }

        let read_res: io::Result<MPCSmall> = if is_large {
            info!("reading large 'after' params as `MPCSmall`: {}", path_after);
            read_small_params_from_large_file(&path_after)
        } else {
            info!("reading small 'after' params as `MPCSmall`: {}", path_after);
            File::open(&path_after).and_then(|file| {
                let mut reader = BufReader::with_capacity(1024 * 1024, file);
                MPCSmall::read(&mut reader, is_raw)
            })
        };

        match read_res {
            Ok(params) => {
                let dt_read = start_read.elapsed().as_secs();
                info!("successfully read 'after' params, dt_read={}s", dt_read);
                after_tx.send(Message::Done(params)).unwrap();
            }
            Err(e) => {
                error!("failed to read 'after' params: {}", e);
                after_tx.send(Message::Error(e)).unwrap();
            }
        };
    });

    let mut before_params: Option<MPCSmall> = None;
    let mut after_params: Option<MPCSmall> = None;

    loop {
        if before_params.is_none() {
            match before_rx.try_recv() {
                Ok(Message::Done(params)) => {
                    before_params = Some(params);
                    info!("received 'before' params from thread");
                }
                Ok(Message::Error(e)) => panic!("'before' thread panic-ed: {}", e),
                Err(TryRecvError::Disconnected) => panic!("'before' thread disconnected"),
                Err(TryRecvError::Empty) => {}
            };
        }

        if after_params.is_none() {
            match after_rx.try_recv() {
                Ok(Message::Done(params)) => {
                    after_params = Some(params);
                    info!("received 'after' params from thread");
                }
                Ok(Message::Error(e)) => panic!("'after' thread panic-ed: {}", e),
                Err(TryRecvError::Disconnected) => panic!("'after' thread disconnected"),
                Err(TryRecvError::Empty) => {}
            };
        }

        if before_params.is_some() && after_params.is_some() {
            break;
        }

        thread::sleep(Duration::from_secs(3));
    }

    before_thread.join().unwrap();
    after_thread.join().unwrap();

    info!("verifying contribution");
    let start_verification = Instant::now();

    let calculated_contrib =
        phase2::small::verify_contribution_small(&before_params.unwrap(), &after_params.unwrap())
            .expect("failed to calculate expected contribution");

    assert_eq!(
        &participant_contrib[..],
        &calculated_contrib[..],
        "provided contribution hash does not match expected contribution hash \
        \n\tprovided: {}\n\texpected: {}",
        hex_string(&participant_contrib),
        hex_string(&calculated_contrib)
    );

    info!(
        "successfully verified contribution, dt_verify={}s, dt_total={}s",
        start_verification.elapsed().as_secs(),
        start_total.elapsed().as_secs()
    );
}

// Non-raw only.
pub fn read_g1<R: Read>(mut reader: R) -> io::Result<G1Affine> {
    let mut affine_bytes = G1Uncompressed::empty();
    reader.read_exact(affine_bytes.as_mut())?;
    let affine = affine_bytes
        .into_affine()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if affine.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deserialized G1Affine is point at infinity",
        ))
    } else {
        Ok(affine)
    }
}

// Non-raw only.
pub fn read_g2<R: Read>(mut reader: R) -> io::Result<G2Affine> {
    let mut affine_bytes = G2Uncompressed::empty();
    reader.read_exact(affine_bytes.as_mut())?;
    let affine = affine_bytes
        .into_affine()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if affine.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "deserialized G2Affine is point at infinity",
        ))
    } else {
        Ok(affine)
    }
}

fn seek(file: &mut File, offset: u64) -> io::Result<()> {
    let pos = file.seek(SeekFrom::Start(offset))?;
    if pos != offset {
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("seek stopped early, reached: {}, expected: {}", pos, offset),
        ))
    } else {
        Ok(())
    }
}

struct FileInfo {
    delta_g1_offset: u64,
    h_len_offset: u64,
    h_len: u64,
    l_len: u64,
    cs_hash: [u8; 64],
    contributions_len_offset: u64,
    contributions_len: u64,
}

impl Debug for FileInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("FileInfo")
            .field("delta_g1_offset", &self.delta_g1_offset)
            .field("h_len_offset", &self.h_len_offset)
            .field("h_len", &self.h_len)
            .field("l_len", &self.l_len)
            .field("cs_hash", &hex_string(&self.cs_hash))
            .field("contributions_len_offset", &self.contributions_len_offset)
            .field("contributions_len", &self.contributions_len)
            .finish()
    }
}

impl FileInfo {
    fn parse_small(path: &str) -> Self {
        let mut file = File::open(path).expect("failed to open file");

        let h_len_offset = G1_SIZE + G2_SIZE;
        seek(&mut file, h_len_offset).expect("failed to seek to h_len");
        let h_len = file.read_u32::<BigEndian>().expect("failed to read h_len") as u64;
        let h_offset = h_len_offset + 4;

        let l_len_offset = h_offset + (h_len * G1_SIZE);
        seek(&mut file, l_len_offset).expect("failed to seek to l_len");
        let l_len = file.read_u32::<BigEndian>().expect("failed to read l_len") as u64;
        let l_offset = l_len_offset + 4;

        let mut cs_hash = [0u8; 64];
        let cs_hash_offset = l_offset + (l_len * G1_SIZE);
        seek(&mut file, cs_hash_offset).expect("failed to seek to cs_hash");
        file.read_exact(&mut cs_hash)
            .expect("failed to read cs_hash");

        let contributions_len_offset = cs_hash_offset + 64;
        let contributions_len = file
            .read_u32::<BigEndian>()
            .expect("failed to read contributions_len") as u64;

        FileInfo {
            delta_g1_offset: 0,
            h_len_offset,
            h_len,
            l_len,
            cs_hash,
            contributions_len_offset,
            contributions_len,
        }
    }

    fn parse_large(path: &str) -> Self {
        let mut file = File::open(path).expect("failed to open file");

        let delta_g1_offset = 2 * G1_SIZE + 2 * G2_SIZE;
        let ic_len_offset = delta_g1_offset + G1_SIZE + G2_SIZE;
        seek(&mut file, ic_len_offset).expect("failed to seek to ic_len");
        let ic_len = file.read_u32::<BigEndian>().expect("failed to read ic_len") as u64;

        let h_len_offset = ic_len_offset + 4 + ic_len * G1_SIZE;
        seek(&mut file, h_len_offset).expect("failed to seek to h_len");
        let h_len = file.read_u32::<BigEndian>().expect("failed to read h_len") as u64;
        let h_offset = h_len_offset + 4;

        let l_len_offset = h_offset + (h_len * G1_SIZE);
        seek(&mut file, l_len_offset).expect("failed to seek to l_len");
        let l_len = file.read_u32::<BigEndian>().expect("failed to read l_len") as u64;
        let l_offset = l_len_offset + 4;

        let a_len_offset = l_offset + (l_len * G1_SIZE);
        seek(&mut file, a_len_offset).expect("failed to seek to a_len");
        let a_len = file.read_u32::<BigEndian>().expect("failed to read a_len") as u64;

        let b_g1_len_offset = a_len_offset + 4 + a_len * G1_SIZE;
        seek(&mut file, b_g1_len_offset).expect("failed to seek to b_g1_len");
        let b_g1_len = file
            .read_u32::<BigEndian>()
            .expect("failed to read b_g1_len") as u64;

        let b_g2_len_offset = b_g1_len_offset + 4 + b_g1_len * G1_SIZE;
        seek(&mut file, b_g2_len_offset).expect("failed to seek to b_g2_len");
        let b_g2_len = file
            .read_u32::<BigEndian>()
            .expect("failed to read b_g2_len") as u64;

        let mut cs_hash = [0u8; 64];
        let cs_hash_offset = b_g2_len_offset + 4 + b_g2_len * G2_SIZE;
        seek(&mut file, cs_hash_offset).expect("failed to seek to cs_hash");
        file.read_exact(&mut cs_hash)
            .expect("failed to read cs_hash");

        let contributions_len_offset = cs_hash_offset + 64;
        let contributions_len = file
            .read_u32::<BigEndian>()
            .expect("failed to read contributions_len") as u64;

        FileInfo {
            delta_g1_offset,
            h_len_offset,
            h_len,
            l_len,
            cs_hash,
            contributions_len_offset,
            contributions_len,
        }
    }
}

// Writes info logs to stdout, error logs to stderr, and all logs to the file `log_filename` in
// `rust-fil-proofs`'s top-level directory.
fn setup_logger(log_filename: &str) {
    let log_file = File::create(&log_filename)
        .unwrap_or_else(|e| panic!("failed to create log file `{}`: {}", log_filename, e));

    let term_logger = TermLogger::new(
        LevelFilter::Info,
        simplelog::Config::default(),
        TerminalMode::Mixed,
    );

    let file_logger = WriteLogger::new(LevelFilter::Info, simplelog::Config::default(), log_file);

    CombinedLogger::init(vec![term_logger, file_logger]).unwrap_or_else(|e| {
        panic!("failed to create `CombinedLogger`: {}", e);
    });
}

#[allow(clippy::cognitive_complexity)]
fn main() {
    let new_command = SubCommand::with_name("new")
        .about("Create initial phase2 parameters for circuit")
        .arg(
            Arg::with_name("sdr")
                .long("sdr")
                .help("Generate SDR PoRep parameters"),
        )
        .arg(
            Arg::with_name("winning")
                .long("winning")
                .help("Generate Winning PoSt parameters"),
        )
        .arg(
            Arg::with_name("window")
                .long("window")
                .help("Generate Window PoSt parameters"),
        )
        .group(
            ArgGroup::with_name("proof")
                .args(&["sdr", "winning", "window"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("2kib")
                .long("2kib")
                .help("Create circuit with 2KiB sector-size"),
        )
        .arg(
            Arg::with_name("4kib")
                .long("4kib")
                .help("Create circuit with 4KiB sector-size"),
        )
        .arg(
            Arg::with_name("16kib")
                .long("16kib")
                .help("Create circuit with 16KiB sector-size"),
        )
        .arg(
            Arg::with_name("32kib")
                .long("32kib")
                .help("Create circuit with 32KiB sector-size"),
        )
        .arg(
            Arg::with_name("8mib")
                .long("8mib")
                .help("Create circuit with 8MiB sector-size"),
        )
        .arg(
            Arg::with_name("16mib")
                .long("16mib")
                .help("Create circuit with 16MiB sector-size"),
        )
        .arg(
            Arg::with_name("512mib")
                .long("512mib")
                .help("Create circuit with 512MiB sector-size"),
        )
        .arg(
            Arg::with_name("1gib")
                .long("1gib")
                .help("Create circuit with 1GiB sector-size"),
        )
        .arg(
            Arg::with_name("32gib")
                .long("32gib")
                .help("Create circuit with 32GiB sector-size"),
        )
        .arg(
            Arg::with_name("64gib")
                .long("64gib")
                .help("Create circuit with 64GiB sector-size"),
        )
        .group(
            ArgGroup::with_name("sector-size")
                .args(&[
                    "2kib", "4kib", "16kib", "32kib", "8mib", "16mib", "512mib", "1gib", "32gib",
                    "64gib",
                ])
                .required(true)
                .multiple(false),
        );

    let contribute_command = SubCommand::with_name("contribute")
        .about("Contribute to parameters")
        .arg(
            Arg::with_name("path-before")
                .required(true)
                .help("The path to the previous participant's params file"),
        )
        .arg(
            Arg::with_name("no-raw")
                .takes_value(false)
                .help("Don't use raw output format (slow to read for next participant)"),
        );
    let contribute_non_streaming_command = SubCommand::with_name("contribute-non-streaming")
        .about("Contribute to parameters")
        .arg(
            Arg::with_name("path-before")
                .required(true)
                .help("The path to the previous participant's params file"),
        );

    let verify_command = SubCommand::with_name("verify")
        .about("Verifies that a contribution transitions one set of params to another")
        .arg(
            Arg::with_name("path-after")
                .required(true)
                .help("The path to the params file containing the contribution to be verified"),
        );

    let small_command = SubCommand::with_name("small")
        .about("Copies a large params file into the small file format")
        .arg(
            Arg::with_name("large-path")
                .required(true)
                .help("The path to the large params file"),
        );

    let convert_command = SubCommand::with_name("convert")
        .about("Converts a small params file to and from raw format")
        .arg(
            Arg::with_name("path-before")
                .required(true)
                .help("The path to the small params file to convert."),
        );

    let merge_command = SubCommand::with_name("merge")
        .about("Merges small-nonraw and large params into a new large file")
        .arg(
            Arg::with_name("path-small")
                .required(true)
                .help("Path to the small params file."),
        )
        .arg(
            Arg::with_name("path-large")
                .required(true)
                .help("Path to the large params file."),
        );

    let matches = App::new("phase2")
        .version("1.0")
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::SubcommandRequired)
        .subcommand(new_command)
        .subcommand(contribute_command)
        .subcommand(contribute_non_streaming_command)
        .subcommand(verify_command)
        .subcommand(small_command)
        .subcommand(convert_command)
        .subcommand(merge_command)
        .get_matches();

    if let (subcommand, Some(matches)) = matches.subcommand() {
        match subcommand {
            "new" => {
                let proof = if matches.is_present("sdr") {
                    Proof::Sdr
                } else if matches.is_present("winning") {
                    Proof::Winning
                } else {
                    Proof::Window
                };

                // Default to using Poseidon for the hasher.
                let hasher = Hasher::Poseidon;

                let sector_size = if matches.is_present("2kib") {
                    Sector::SectorSize2KiB
                } else if matches.is_present("4kib") {
                    Sector::SectorSize4KiB
                } else if matches.is_present("16kib") {
                    Sector::SectorSize16KiB
                } else if matches.is_present("32kib") {
                    Sector::SectorSize32KiB
                } else if matches.is_present("8mib") {
                    Sector::SectorSize8MiB
                } else if matches.is_present("16mib") {
                    Sector::SectorSize16MiB
                } else if matches.is_present("512mib") {
                    Sector::SectorSize512MiB
                } else if matches.is_present("1gib") {
                    Sector::SectorSize1GiB
                } else if matches.is_present("32gib") {
                    Sector::SectorSize32GiB
                } else {
                    Sector::SectorSize64GiB
                };

                let head = get_head_commit();
                let mut log_filename = params_filename(
                    proof,
                    hasher,
                    sector_size,
                    &head,
                    0,
                    ParamSize::Large,
                    false,
                );
                log_filename.push_str(".log");
                setup_logger(&log_filename);

                with_shape!(
                    sector_size.as_u64(),
                    create_initial_params,
                    proof,
                    hasher,
                    sector_size
                );
            }
            "contribute" => {
                let path_before = matches.value_of("path-before").unwrap();
                let raw = !matches.is_present("no-raw");

                let (proof, hasher, sector_size, head, param_num_before, _param_size, _read_raw) =
                    parse_params_filename(path_before);

                let param_num = param_num_before + 1;

                // Default to small contributions.
                let mut log_filename = params_filename(
                    proof,
                    hasher,
                    sector_size,
                    &head,
                    param_num,
                    ParamSize::Small,
                    raw,
                );
                log_filename.push_str(".log");
                setup_logger(&log_filename);

                contribute_to_params_streaming(path_before, raw);
            }
            "contribute-non-streaming" => {
                // This path only exists to test streaming vs non-streaming.

                let path_before = matches.value_of("path-before").unwrap();

                let (proof, hasher, sector_size, head, param_num_before, _param_size, _read_raw) =
                    parse_params_filename(path_before);
                let param_num = param_num_before + 1;

                // Default to small contributions.
                let mut log_filename = params_filename(
                    proof,
                    hasher,
                    sector_size,
                    &head,
                    param_num,
                    ParamSize::Small,
                    false,
                );
                log_filename.push_str(".log");
                setup_logger(&log_filename);
                contribute_to_params(path_before);
            }
            "verify" => {
                let path_after = matches.value_of("path-after").unwrap();

                assert!(
                    Path::new(&path_after).exists(),
                    "'after' params path does not exist: `{}`",
                    path_after
                );

                let (proof, hasher, sector_size, head, param_num_after, _, _) =
                    parse_params_filename(path_after);

                let log_filename = format!("{}_verify.log", path_after);
                setup_logger(&log_filename);

                // Default to using small-raw before params, fallback to non-raw params if raw do
                // not exist.
                let path_before = {
                    let small_raw = params_filename(
                        proof,
                        hasher,
                        sector_size,
                        &head,
                        param_num_after - 1,
                        ParamSize::Small,
                        true,
                    );
                    let small_nonraw = small_raw.trim_end_matches("_raw").to_string();
                    let large = small_nonraw.replace("small", "large");

                    if Path::new(&small_raw).exists() {
                        info!("found small-raw 'before' params: {}", small_raw);
                        small_raw
                    } else if Path::new(&small_nonraw).exists() {
                        info!("found small-nonraw 'before' params: {}", small_nonraw);
                        small_nonraw
                    } else if Path::new(&large).exists() {
                        info!("found large 'before' params: {}", large);
                        large
                    } else {
                        let err_msg = format!(
                            "no 'before' params found, attempted: {}, {}, {}",
                            small_raw, small_nonraw, large
                        );
                        error!("{}", err_msg);
                        panic!("{}", err_msg);
                    }
                };

                let mut contrib_path = format!("{}.contrib", path_after);

                // It is possible that the .contrib file was generated using a param-size or
                // serialization format that differs from those in `path_after`, in which case we
                // need to search for the .contrib file.
                if !Path::new(&contrib_path).exists() {
                    warn!("contrib file not found: {}", contrib_path);
                    let mut found_contrib_file = false;
                    for _ in 0..2 {
                        contrib_path = if contrib_path.ends_with("large.contrib") {
                            contrib_path.replace("large", "small")
                        } else if contrib_path.ends_with("small.contrib") {
                            contrib_path.replace("small", "small_raw")
                        } else {
                            contrib_path.replace("small_raw", "large")
                        };
                        info!("trying contrib file: {}", contrib_path);
                        if Path::new(&contrib_path).exists() {
                            found_contrib_file = true;
                            break;
                        }
                        warn!("contrib file not found");
                    }
                    if !found_contrib_file {
                        error!("no contrib file found");
                        panic!("no contrib file found");
                    }
                }
                info!("using contrib file: {}", contrib_path);

                let contrib = {
                    let mut bytes = [0u8; 64];
                    let hex_str = fs::read_to_string(&contrib_path).unwrap_or_else(|e| {
                        panic!("failed to read contribution file `{}`: {}", contrib_path, e);
                    });
                    let bytes_vec = hex::decode(&hex_str).unwrap_or_else(|_| {
                        panic!(
                            "contribution found in file `{}` is not a valid hex string: {}",
                            contrib_path, hex_str
                        );
                    });
                    let n_bytes = bytes_vec.len();
                    assert_eq!(
                        n_bytes, 64,
                        "contribution file's `{}` hex string must represent 64 bytes, \
                        found {} bytes",
                        contrib_path, n_bytes
                    );
                    bytes.copy_from_slice(&bytes_vec[..]);
                    bytes
                };

                verify_contribution(&path_before, &path_after, contrib);
            }
            "small" => {
                let large_path = matches.value_of("large-path").unwrap();

                let (proof, hasher, sector_size, head, param_num, param_size, read_raw) =
                    parse_params_filename(large_path);

                assert!(param_size.is_large(), "param file is not in large format");
                assert!(!read_raw, "param file is in raw format");

                let small_path = params_filename(
                    proof,
                    hasher,
                    sector_size,
                    &head,
                    param_num,
                    ParamSize::Small,
                    false,
                );

                println!("reading small params from large file: {}", large_path);
                let small_params =
                    read_small_params_from_large_file(&large_path).unwrap_or_else(|e| {
                        panic!("failed to read large params `{}`: {}", large_path, e)
                    });

                let start_read = Instant::now();
                let small_file = File::create(&small_path).unwrap_or_else(|e| {
                    panic!("failed to create small params file `{}`: {}", small_path, e);
                });
                println!(
                    "successfully read small params from large, dt_read={}s",
                    start_read.elapsed().as_secs()
                );

                let mut writer = BufWriter::with_capacity(1024 * 1024, small_file);

                println!("writing small params to file: {}", small_path);
                small_params.write(&mut writer).unwrap_or_else(|e| {
                    panic!(
                        "failed to write small params to file `{}`: {}",
                        small_path, e
                    );
                });

                println!("successfully wrote small params");
            }
            "convert" => {
                let path_before = matches.value_of("path-before").unwrap();

                let log_filename = format!("{}_convert.log", path_before);
                setup_logger(&log_filename);

                convert_small(path_before)
            }
            "merge" => {
                let path_small = matches.value_of("path-small").unwrap();
                let path_large_old = matches.value_of("path-large").unwrap();

                assert!(
                    Path::new(path_small).exists(),
                    "small file does not exist: {}",
                    path_small
                );
                assert!(
                    Path::new(path_large_old).exists(),
                    "large file does not exist: {}",
                    path_large_old
                );

                let (
                    proof_small,
                    hasher_small,
                    sector_size_small,
                    head_small,
                    param_num_small,
                    param_size_small,
                    is_raw_small,
                ) = parse_params_filename(path_small);

                let (
                    proof_large,
                    hasher_large,
                    sector_size_large,
                    head_large,
                    param_num_large,
                    param_size_large,
                    _,
                ) = parse_params_filename(path_large_old);

                assert!(
                    param_size_small.is_small(),
                    "small params file is not small"
                );
                assert!(
                    param_size_large.is_large(),
                    "large params file is not large"
                );
                assert_eq!(
                    proof_small, proof_large,
                    "small and large params do not have the same proof name"
                );
                assert_eq!(
                    hasher_small, hasher_large,
                    "small and large params do not have the same hasher name"
                );
                assert_eq!(
                    sector_size_small, sector_size_large,
                    "small and large params do not have the same sector-size name"
                );
                assert_eq!(
                    head_small, head_large,
                    "small and large params do not have the same head commit"
                );
                assert!(
                    param_num_small > param_num_large,
                    "small params must contain more contributions than the large"
                );
                assert!(!is_raw_small, "small params must be non-raw");

                let FileInfo {
                    h_len: h_len_small,
                    l_len: l_len_small,
                    cs_hash: cs_hash_small,
                    contributions_len_offset: contributions_len_offset_small,
                    contributions_len: contributions_len_small,
                    ..
                } = FileInfo::parse_small(&path_small);
                println!("parsed small file");

                let FileInfo {
                    delta_g1_offset: delta_g1_offset_large,
                    h_len_offset: h_len_offset_large,
                    h_len: h_len_large,
                    l_len: l_len_large,
                    cs_hash: cs_hash_large,
                    contributions_len_offset: contributions_len_offset_large,
                    contributions_len: contributions_len_large,
                } = FileInfo::parse_large(&path_large_old);
                println!("parsed large file");

                assert_eq!(
                    h_len_small, h_len_large,
                    "parsed files have different h_len: small: {}, large: {}",
                    h_len_small, h_len_large
                );
                let h_len = h_len_small;
                assert_eq!(
                    l_len_small, l_len_large,
                    "parsed files have different l_len: small: {}, large: {}",
                    l_len_small, l_len_large,
                );
                let l_len = l_len_small;
                assert_eq!(
                    &cs_hash_small[..],
                    &cs_hash_large[..],
                    "parsed files have different cs_hash: small: {:?}, large: {:?}",
                    &cs_hash_small[..],
                    &cs_hash_large[..],
                );
                assert!(
                    contributions_len_small > contributions_len_large,
                    "small file does not contain additional contributions, small: {}, large: {}",
                    contributions_len_small,
                    contributions_len_large
                );
                println!("files are consistent");

                println!("copying large file");
                let path_large_new = path_small.replace("small", "large");
                let large_len_old =
                    fs::copy(&path_large_old, &path_large_new).expect("failed to copy large file");
                let append_len = (contributions_len_small - contributions_len_large) * PUBKEY_SIZE;
                let large_len_new = large_len_old + append_len;
                let mut file_large_new = OpenOptions::new()
                    .write(true)
                    .open(&path_large_new)
                    .expect("failed to open new large file");
                file_large_new
                    .set_len(large_len_new)
                    .expect("failed to set new large file length");

                println!("merging small file into copy");
                let mut file_small = File::open(path_small).expect("failed to open small file");

                // Copy delta_g1/g2
                let mut delta_bytes = (&mut file_small).take(G1_SIZE + G2_SIZE);
                seek(&mut file_large_new, delta_g1_offset_large)
                    .expect("failed to seek to delta_g1 in new file");
                io::copy(&mut delta_bytes, &mut file_large_new)
                    .expect("failed to merge delta_g1/g2");
                println!("merged delta_g1/g2");

                // Copy h_len, h, l_len, l
                let mut h_l_bytes = (&mut file_small).take((h_len + l_len) * G1_SIZE + 8);
                seek(&mut file_large_new, h_len_offset_large)
                    .expect("failed to seek to h in new file");
                io::copy(&mut h_l_bytes, &mut file_large_new)
                    .expect("failed to merge h, h_len, and l");
                println!("merged h_len, h, l_len, and l");

                // Copy contributions_len and contributions
                seek(&mut file_small, contributions_len_offset_small)
                    .expect("failed to seek to contributions_len in small file");
                seek(&mut file_large_new, contributions_len_offset_large)
                    .expect("failed to seek to contributions_len in new file");
                io::copy(&mut file_small, &mut file_large_new)
                    .expect("failed to merge contributions");
                println!("merged contributions");

                println!("successfully merged");
            }
            _ => unreachable!(),
        }
    }
}
