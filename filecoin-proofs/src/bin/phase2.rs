use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::path::Path;
use std::process::Command;
use std::str::{self, FromStr};
use std::sync::mpsc::{channel, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bellperson::bls::{Bls12, G1Affine, G1Uncompressed, G2Affine, G2Uncompressed};
use bellperson::groth16;
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
use phase2::small::{read_small_params_from_large_file, MPCSmall, Streamer};
use phase2::MPCParameters;
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use simplelog::{self, CombinedLogger, LevelFilter, TermLogger, TerminalMode, WriteLogger};
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::hasher::Sha256Hasher;
use storage_proofs::merkle::MerkleTreeTrait;
use storage_proofs::parameter_cache::{
    self, metadata_id, parameter_id, verifying_key_id, CacheableParameters,
};
use storage_proofs::porep::stacked::{
    PublicParams as PoRepPublicParams, StackedCircuit, StackedCompound, StackedDrg,
};
use storage_proofs::post::fallback::{
    FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound, PublicParams as PoStPublicParams,
};

const CHUNK_SIZE: usize = 10_000;

// Non-raw sizes.
const G1_SIZE: u64 = size_of::<G1Uncompressed>() as u64; // 96
const G2_SIZE: u64 = size_of::<G2Uncompressed>() as u64; // 192
const PUBKEY_SIZE: u64 = 3 * G1_SIZE + G2_SIZE + 64; // 544

const VEC_LEN_SIZE: u64 = size_of::<u32>() as u64; // 4

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
}

impl Hasher {
    // Used for printing during logging. Implementing Debug and Display is less clear than having
    // methods `.pretty_print()` and `.lowercase()` which differentiate between printing for logging
    // v.s. printing for filenames.
    fn pretty_print(&self) -> &str {
        match self {
            Hasher::Poseidon => "Poseidon",
        }
    }

    // Used for constructing param filenames.
    fn lowercase(&self) -> &str {
        match self {
            Hasher::Poseidon => "poseidon",
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
// (proof, hasher, sector-size, head, param-number, param-size, is-raw).
fn parse_params_filename(path: &str) -> (Proof, Hasher, Sector, String, usize, ParamSize, bool) {
    // Remove directories from the path.
    let filename = path
        .rsplitn(2, '/')
        .next()
        .expect("parse_params_filename rsplitn failed");
    let split: Vec<&str> = filename.split('_').collect();

    let proof = match split[0] {
        "sdr" => Proof::Sdr,
        "winning" => Proof::Winning,
        "window" => Proof::Window,
        other => panic!("invalid proof name in params filename: {}", other),
    };

    let hasher = match split[1] {
        "poseidon" => Hasher::Poseidon,
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

    if param_size.is_large() && raw_fmt {
        unimplemented!("large-raw params are not currently supported: {}", path);
    }

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

fn blank_sdr_poseidon_params<Tree: MerkleTreeTrait>(sector_size: u64) -> PoRepPublicParams<Tree> {
    let n_partitions = *POREP_PARTITIONS
        .read()
        .expect("porep partition read error")
        .get(&sector_size)
        .expect("porep partition get error");

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
        .expect("failed to setup params"),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
        priority: false,
    };

    let public_params = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
        StackedDrg<Tree, Sha256Hasher>,
        _,
    >>::setup(&setup_params)
    .expect("public param setup failed");
    public_params.vanilla_params
}

fn blank_winning_post_poseidon_params<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
) -> PoStPublicParams {
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        sector_count: WINNING_POST_SECTOR_COUNT,
        typ: PoStType::Winning,
        priority: false,
    };

    winning_post_public_params::<Tree>(&post_config).expect("winning post public params failed")
}

fn blank_window_post_poseidon_params<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
) -> PoStPublicParams {
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        sector_count: *WINDOW_POST_SECTOR_COUNT
            .read()
            .expect("post config sector count read failure")
            .get(&sector_size)
            .expect("post config sector count get failure"),
        typ: PoStType::Window,
        priority: false,
    };

    window_post_public_params::<Tree>(&post_config).expect("window post public params failed")
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
            let public_params = blank_sdr_poseidon_params(sector_size.as_u64());
            let circuit = <StackedCompound<Tree, Sha256Hasher> as CompoundProof<
                StackedDrg<Tree, Sha256Hasher>,
                _,
            >>::blank_circuit(&public_params);
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = MPCParameters::new(circuit).expect("mpc params new failure");
            dt_create_params = start.elapsed().as_secs();
            params
        }
        (Proof::Winning, Hasher::Poseidon) => {
            let start = Instant::now();
            let public_params = blank_winning_post_poseidon_params::<Tree>(sector_size.as_u64());
            let circuit = <FallbackPoStCompound<Tree> as CompoundProof<
                FallbackPoSt<Tree>,
                FallbackPoStCircuit<Tree>,
            >>::blank_circuit(&public_params);
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = MPCParameters::new(circuit).expect("mpc params new failure");
            dt_create_params = start.elapsed().as_secs();
            params
        }
        (Proof::Window, Hasher::Poseidon) => {
            let start = Instant::now();
            let public_params = blank_window_post_poseidon_params::<Tree>(sector_size.as_u64());
            let circuit = <FallbackPoStCompound<Tree> as CompoundProof<
                FallbackPoSt<Tree>,
                FallbackPoStCircuit<Tree>,
            >>::blank_circuit(&public_params);
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = MPCParameters::new(circuit).expect("mpc params new failure");
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

    {
        info!("writing large initial params to file: {}", large_path);
        let file = File::create(&large_path).expect("param file create failure");
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        params.write(&mut writer).expect("param file write failure");
        info!("finished writing large params to file");
    }

    // TODO: add conversion from large to small params to phase2 crate, then write initial params as
    // small-raw.
    /*
    let small_path = params_filename(proof, hasher, sector_size, &head, 0, ParamSize::Small, true);
    {
        info!("writing small initial params to file: {}", small_path);
        let file = File::create(&small_path).unwrap();
        let mut writer = BufWriter::with_capacity(1024 * 1024, file);
        params.write_small(&mut writer).unwrap();
        info!("finished writing small params to file");
    }
    */

    info!(
        "successfully created and wrote initial params for circuit: {}-{}-{}-{}, dt_total={}s",
        proof.pretty_print(),
        hasher.pretty_print(),
        sector_size.pretty_print(),
        head,
        start_total.elapsed().as_secs()
    );
}

fn hex_string(contrib: &[u8]) -> String {
    hex::encode(contrib)
}

fn get_mixed_entropy() -> [u8; 32] {
    use dialoguer::theme::ColorfulTheme;
    use dialoguer::Password;

    let mut os_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut os_entropy);

    let user_input = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Please randomly press your keyboard (press Return/Enter when finished)")
        .interact()
        .expect("entropy read failure");

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

/// Contributes entropy to the current phase2 parameters for a circuit, then writes the new params
/// to a small-raw file.
fn contribute_to_params(path_before: &str, seed: Option<[u8; 32]>) {
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

    // Get OS entropy prior to deserializing the previous params.
    let seed = if let Some(seed) = seed {
        warn!("using `seed` argument as entropy: {}", hex_string(&seed));
        seed
    } else {
        info!("using mixed entropy");
        get_mixed_entropy()
    };
    let mut rng = ChaChaRng::from_seed(seed);

    // Write small-raw contributions.
    let path_after = params_filename(
        proof,
        hasher,
        sector_size,
        &head,
        param_number,
        ParamSize::Small,
        true,
    );

    let start_total = Instant::now();

    info!("making contribution");
    let start_contrib = Instant::now();

    let mut streamer = if param_size.is_large() {
        Streamer::new_from_large_file(path_before, read_raw, true).unwrap_or_else(|e| {
            panic!(
                "failed to make streamer from large `{}`: {}",
                path_before, e
            );
        })
    } else {
        Streamer::new(path_before, read_raw, true).unwrap_or_else(|e| {
            panic!(
                "failed to make streamer from small `{}`: {}",
                path_before, e
            );
        })
    };

    let file_after = File::create(&path_after).unwrap_or_else(|e| {
        panic!(
            "failed to create 'after' params file `{}`: {}",
            path_after, e
        );
    });

    info!("streaming 'after' params to file: {}", path_after);
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

/// If `raw_subgroup_checks` is true, then `verify_contribution` ensures that the G1 points of the 'after' contribution
/// are in the correct subgroup. This is expensive, so the 'before' contribution is not checked. This assumes that all
/// 'after' contributions will be separately verified, and ensures that the subgroup check will happen once (but no
/// more). This means the very first 'before' params will not have the subgroup check. However, the verifier will have
/// constructed these deterministically such that they are known to be in the subgroup.
fn verify_contribution(
    path_before: &str,
    path_after: &str,
    participant_contrib: [u8; 64],
    raw_subgroup_checks: bool,
) {
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

        if is_raw {
            warn!("skipping subgroup checks when deserializing small-raw 'before' params");
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
                MPCSmall::read(&mut reader, is_raw, false)
            })
        };

        match read_res {
            Ok(params) => {
                let dt_read = start_read.elapsed().as_secs();
                info!("successfully read 'before' params, dt_read={}s", dt_read);
                before_tx.send(Message::Done(params)).expect("send failure");
            }
            Err(e) => {
                error!("failed to read 'before' params: {}", e);
                before_tx.send(Message::Error(e)).expect("send failure");
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

        if is_raw && !raw_subgroup_checks {
            warn!("skipping subgroup checks when deserializing small-raw 'after' params")
        }

        let read_res: io::Result<MPCSmall> = if is_large {
            info!("reading large 'after' params as `MPCSmall`: {}", path_after);
            read_small_params_from_large_file(&path_after)
        } else {
            info!("reading small 'after' params as `MPCSmall`: {}", path_after);
            File::open(&path_after).and_then(|file| {
                let mut reader = BufReader::with_capacity(1024 * 1024, file);
                MPCSmall::read(&mut reader, is_raw, raw_subgroup_checks)
            })
        };

        match read_res {
            Ok(params) => {
                let dt_read = start_read.elapsed().as_secs();
                info!("successfully read 'after' params, dt_read={}s", dt_read);
                after_tx.send(Message::Done(params)).expect("send failure");
            }
            Err(e) => {
                error!("failed to read 'after' params: {}", e);
                after_tx.send(Message::Error(e)).expect("send failure");
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

    before_thread.join().expect("thread join failure");
    after_thread.join().expect("thread join failure");

    info!("verifying contribution");
    let start_verification = Instant::now();

    let calculated_contrib = phase2::small::verify_contribution_small(
        &before_params.expect("before params failure"),
        &after_params.expect("after params failure"),
    )
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
    delta_g1: G1Affine,
    delta_g2: G2Affine,
    h_len_offset: u64,
    h_len: u64,
    h_first: G1Affine,
    h_last: G1Affine,
    l_len: u64,
    l_first: G1Affine,
    l_last: G1Affine,
    cs_hash: [u8; 64],
    contributions_len_offset: u64,
    contributions_len: u64,
}

impl Debug for FileInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("FileInfo")
            .field("delta_g1_offset", &self.delta_g1_offset)
            .field("delta_g1", &self.delta_g1)
            .field("delta_g2", &self.delta_g2)
            .field("h_len_offset", &self.h_len_offset)
            .field("h_len", &self.h_len)
            .field("h_first", &self.h_first)
            .field("h_last", &self.h_last)
            .field("l_len", &self.l_len)
            .field("l_first", &self.l_first)
            .field("l_last", &self.l_last)
            .field("cs_hash", &hex_string(&self.cs_hash))
            .field("contributions_len_offset", &self.contributions_len_offset)
            .field("contributions_len", &self.contributions_len)
            .finish()
    }
}

impl FileInfo {
    fn parse_small(path: &str) -> Self {
        let mut file = File::open(path).expect("failed to open file");

        let delta_g1 = read_g1(&mut file).expect("failed to read delta_g1");
        let delta_g2 = read_g2(&mut file).expect("failed to read delta_g2");

        let h_len_offset = G1_SIZE + G2_SIZE;
        let h_len = file.read_u32::<BigEndian>().expect("failed to read h_len") as u64;
        let h_first = read_g1(&mut file).expect("failed to read first h element");
        let h_last_offset = h_len_offset + VEC_LEN_SIZE + (h_len - 1) * G1_SIZE;
        seek(&mut file, h_last_offset).expect("failed to seek to last h element");
        let h_last = read_g1(&mut file).expect("failed to read last h element");

        let l_len_offset = h_last_offset + G1_SIZE;
        let l_len = file.read_u32::<BigEndian>().expect("failed to read l_len") as u64;
        let l_first = read_g1(&mut file).expect("failed to read first l element");
        let l_last_offset = l_len_offset + VEC_LEN_SIZE + (l_len - 1) * G1_SIZE;
        seek(&mut file, l_last_offset).expect("failed to seek to last l element");
        let l_last = read_g1(&mut file).expect("failed to read last l element");

        let mut cs_hash = [0u8; 64];
        let cs_hash_offset = l_last_offset + G1_SIZE;
        seek(&mut file, cs_hash_offset).expect("failed to seek to cs_hash");
        file.read_exact(&mut cs_hash)
            .expect("failed to read cs_hash");

        let contributions_len_offset = cs_hash_offset + 64;
        let contributions_len = file
            .read_u32::<BigEndian>()
            .expect("failed to read contributions_len") as u64;

        FileInfo {
            delta_g1_offset: 0,
            delta_g1,
            delta_g2,
            h_len_offset,
            h_len,
            h_first,
            h_last,
            l_len,
            l_first,
            l_last,
            cs_hash,
            contributions_len_offset,
            contributions_len,
        }
    }

    fn parse_large(path: &str) -> Self {
        let mut file = File::open(path).expect("failed to open file");

        let delta_g1_offset = 2 * G1_SIZE + 2 * G2_SIZE;
        seek(&mut file, delta_g1_offset).expect("failed to seek to delta_g1");
        let delta_g1 = read_g1(&mut file).expect("failed to read delta_g1");
        let delta_g2 = read_g2(&mut file).expect("failed to read delta_g2");

        let ic_len_offset = delta_g1_offset + G1_SIZE + G2_SIZE;
        let ic_len = file.read_u32::<BigEndian>().expect("failed to read ic_len") as u64;

        let h_len_offset = ic_len_offset + VEC_LEN_SIZE + ic_len * G1_SIZE;
        seek(&mut file, h_len_offset).expect("failed to seek to h_len");
        let h_len = file.read_u32::<BigEndian>().expect("failed to read h_len") as u64;
        let h_first = read_g1(&mut file).expect("failed to read first h element");
        let h_last_offset = h_len_offset + VEC_LEN_SIZE + (h_len - 1) * G1_SIZE;
        seek(&mut file, h_last_offset).expect("failed to seek to last h element");
        let h_last = read_g1(&mut file).expect("failed to read last h element");

        let l_len_offset = h_last_offset + G1_SIZE;
        let l_len = file.read_u32::<BigEndian>().expect("failed to read l_len") as u64;
        let l_first = read_g1(&mut file).expect("failed to read first l element");
        let l_last_offset = l_len_offset + VEC_LEN_SIZE + (l_len - 1) * G1_SIZE;
        seek(&mut file, l_last_offset).expect("failed to seek to last l element");
        let l_last = read_g1(&mut file).expect("failed to read last l element");

        let a_len_offset = l_last_offset + G1_SIZE;
        seek(&mut file, a_len_offset).expect("failed to seek to a_len");
        let a_len = file.read_u32::<BigEndian>().expect("failed to read a_len") as u64;

        let b_g1_len_offset = a_len_offset + VEC_LEN_SIZE + a_len * G1_SIZE;
        seek(&mut file, b_g1_len_offset).expect("failed to seek to b_g1_len");
        let b_g1_len = file
            .read_u32::<BigEndian>()
            .expect("failed to read b_g1_len") as u64;

        let b_g2_len_offset = b_g1_len_offset + VEC_LEN_SIZE + b_g1_len * G1_SIZE;
        seek(&mut file, b_g2_len_offset).expect("failed to seek to b_g2_len");
        let b_g2_len = file
            .read_u32::<BigEndian>()
            .expect("failed to read b_g2_len") as u64;

        let mut cs_hash = [0u8; 64];
        let cs_hash_offset = b_g2_len_offset + VEC_LEN_SIZE + b_g2_len * G2_SIZE;
        seek(&mut file, cs_hash_offset).expect("failed to seek to cs_hash");
        file.read_exact(&mut cs_hash)
            .expect("failed to read cs_hash");

        let contributions_len_offset = cs_hash_offset + 64;
        let contributions_len = file
            .read_u32::<BigEndian>()
            .expect("failed to read contributions_len") as u64;

        FileInfo {
            delta_g1_offset,
            delta_g1,
            delta_g2,
            h_len_offset,
            h_len,
            h_first,
            h_last,
            l_len,
            l_first,
            l_last,
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

fn parameter_identifier<Tree: 'static + MerkleTreeTrait>(sector_size: u64, proof: Proof) -> String {
    match proof {
        Proof::Sdr => {
            let public_params = blank_sdr_poseidon_params::<Tree>(sector_size);

            <StackedCompound<Tree, Sha256Hasher> as CacheableParameters<
                StackedCircuit<Tree, Sha256Hasher>,
                _,
            >>::cache_identifier(&public_params)
        }
        Proof::Winning => {
            let public_params = blank_winning_post_poseidon_params::<Tree>(sector_size);
            <FallbackPoStCompound<Tree> as CacheableParameters<
                            FallbackPoStCircuit<Tree>,
                            _,
                        >>::cache_identifier(&public_params)
        }
        Proof::Window => {
            let public_params = blank_window_post_poseidon_params::<Tree>(sector_size);
            <FallbackPoStCompound<Tree> as CacheableParameters<
                           FallbackPoStCircuit<Tree>,
                           _,
                        >>::cache_identifier(&public_params)
        }
    }
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
            Arg::with_name("seed")
                .long("seed")
                .takes_value(true)
                .help("Sets the contribution entropy (32 hex bytes)"),
        );

    let verify_command = SubCommand::with_name("verify")
        .about("Verifies that a contribution transitions one set of params to another")
        .arg(
            Arg::with_name("path-after")
                .required(true)
                .help("The path to the params file containing the contribution to be verified"),
        )
        .arg(
            Arg::with_name("skip-raw-subgroup-checks")
                .long("skip-raw-subgroup-checks")
                .short("s")
                .help("Skip the slow subgroup check when deserializing each raw G1 point"),
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

    let split_keys_command = SubCommand::with_name("split-keys")
        .about("Splits the keys from the trusted setup into parameter files")
        .arg(
            Arg::with_name("input-path")
                .required(true)
                .help("The path to the file that contains all the data."),
        );

    let parse_command = SubCommand::with_name("parse")
        .about("Parses file info from large or small-nonraw params")
        .arg(
            Arg::with_name("path")
                .required(true)
                .help("Path to params file."),
        );

    let verify_g1_command = SubCommand::with_name("verify-g1")
        .about("Verifies that all points in small-raw params are valid G1")
        .arg(
            Arg::with_name("path")
                .required(true)
                .help("Path to small-raw params file."),
        );

    let matches = App::new("phase2")
        .version("1.0")
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::SubcommandRequired)
        .subcommand(new_command)
        .subcommand(contribute_command)
        .subcommand(verify_command)
        .subcommand(small_command)
        .subcommand(convert_command)
        .subcommand(merge_command)
        .subcommand(split_keys_command)
        .subcommand(parse_command)
        .subcommand(verify_g1_command)
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
                let path_before = matches
                    .value_of("path-before")
                    .expect("path-before match failure");

                let seed: Option<[u8; 32]> = matches.value_of("seed").map(|hex_str| {
                    assert_eq!(
                        hex_str.chars().count(),
                        64,
                        "`seed` argument must be exactly 64 characters long, found {} characters",
                        hex_str.chars().count()
                    );
                    let mut seed = [0u8; 32];
                    let seed_vec = hex::decode(hex_str).unwrap_or_else(|_| {
                        panic!("`seed` argument is not a valid hex string: {}", hex_str);
                    });
                    seed.copy_from_slice(&seed_vec[..]);
                    seed
                });

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
                    true,
                );
                log_filename.push_str(".log");
                setup_logger(&log_filename);

                contribute_to_params(path_before, seed);
            }
            "verify" => {
                let path_after = matches
                    .value_of("path-after")
                    .expect("path-after match failure");
                let raw_subgroup_checks = !matches.is_present("skip-raw-subgroup-checks");

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

                verify_contribution(&path_before, &path_after, contrib, raw_subgroup_checks);
            }
            "small" => {
                let large_path = matches
                    .value_of("large-path")
                    .expect("large-path match failure");

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
                let path_before = matches
                    .value_of("path-before")
                    .expect("path-before match failure");

                let log_filename = format!("{}_convert.log", path_before);
                setup_logger(&log_filename);

                convert_small(path_before)
            }
            "merge" => {
                let path_small = matches
                    .value_of("path-small")
                    .expect("path-small match failure");
                let path_large_old = matches
                    .value_of("path-large")
                    .expect("path-large match failure");

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
                    ..
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
                let mut h_l_bytes = (&mut file_small)
                    .take(VEC_LEN_SIZE + h_len * G1_SIZE + VEC_LEN_SIZE + l_len * G1_SIZE);
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
            "split-keys" => {
                let input_path = matches
                    .value_of("input-path")
                    .expect("failed to read input-path argument");

                println!("reading params: {}", input_path);

                // Get the identifier for the output files based in the input file's name
                let (proof, _hasher, sector_size_enum, _head, param_num, param_size, _read_raw) =
                    parse_params_filename(input_path);
                assert!(param_size.is_large(), "params must be large");
                let sector_size = sector_size_enum.as_u64();
                let identifier = with_shape!(sector_size, parameter_identifier, sector_size, proof);

                let mut input_file = File::open(input_path)
                    .unwrap_or_else(|_| panic!("failed to open {}", input_path));

                // Extract the vk data into its own file.
                {
                    let vk_data = groth16::VerifyingKey::<Bls12>::read(&input_file)
                        .expect("failed to deserialize vk from input file");
                    let vk_path = verifying_key_id(&identifier);
                    println!("writing verifying key to file: {}", vk_path);
                    let mut vk_file = File::create(&vk_path)
                        .unwrap_or_else(|_| panic!("failed to create {}", vk_path));
                    vk_data.write(&mut vk_file).unwrap_or_else(|_| {
                        panic!("failed to write verification keys to file {}", vk_path)
                    });
                    let vk_file_size = vk_file
                        .seek(SeekFrom::Current(0))
                        .unwrap_or_else(|_| panic!("failed to seek in {}", vk_path));
                    println!("size of the verifying key is {} bytes", vk_file_size);
                }

                // The params file is the trusted setup phase2 result without the contributions
                // at the end of the file.
                {
                    let params_path = parameter_id(&identifier);
                    println!("writing parameters to file: {}", params_path);
                    let mut params_file = File::create(&params_path)
                        .unwrap_or_else(|_| panic!("failed to create {}", params_path));

                    // input_file_size - cs_hash - contributions_length -
                    //   (num_contributions * public_key_size)
                    let params_file_size = input_file
                        .metadata()
                        .unwrap_or_else(|_| panic!("failed to get filesize of {}", input_path))
                        .len()
                        - 64
                        - 4
                        - (param_num as u64 * 544);
                    println!("size of the parameters file is {} bytes", params_file_size);
                    // Make sure the cursor is at the beginning of the file (it was moved
                    // during the extraction of the vk data)
                    input_file
                        .seek(SeekFrom::Start(0))
                        .expect("cannot seek to beginning of the input file");

                    io::copy(
                        &mut Read::by_ref(&mut input_file).take(params_file_size),
                        &mut params_file,
                    )
                    .unwrap_or_else(|_| {
                        panic!(
                            "Failed to copy params from {} to {}",
                            input_path, params_path
                        )
                    });
                }

                // Writing the contributions to disk is not needed for the final parameters,
                // they won't be published, they are only there for verification purpose.
                {
                    let contribs_path =
                        format!("v{}-{}.contribs", parameter_cache::VERSION, &identifier);
                    println!("writing contributions to file: {}", contribs_path);
                    let mut contribs_file = File::create(&contribs_path)
                        .unwrap_or_else(|_| panic!("failed to create {}", contribs_path));
                    // The input file is already sought to the right offset, due to writing the
                    // params file
                    let contribs_file_size = io::copy(&mut input_file, &mut contribs_file)
                        .unwrap_or_else(|_| {
                            panic!(
                                "Failed to copy contributions from {} to {}",
                                input_path, contribs_path
                            )
                        });
                    println!(
                        "size of the contributions file is {} bytes",
                        contribs_file_size
                    );
                }

                // The metadata is needed for the publication of the parameters.
                {
                    let meta_path = metadata_id(&identifier);
                    println!("writing metadata to file: {}", meta_path);
                    let mut meta_file = File::create(&meta_path)
                        .unwrap_or_else(|_| panic!("failed to create {}", meta_path));
                    write!(&mut meta_file, r#"{{"sector_size":{}}}"#, sector_size).unwrap_or_else(
                        |_| panic!("failed to write meta information to {}", meta_path),
                    );
                }

                // The info file contains the filename the parameter was created of.
                {
                    let info_path = format!("v{}-{}.info", parameter_cache::VERSION, &identifier);
                    println!("writing info to file: {}", info_path);
                    let mut info_file = File::create(&info_path)
                        .unwrap_or_else(|_| panic!("failed to create {}", info_path));
                    writeln!(&mut info_file, "{}", input_path)
                        .unwrap_or_else(|_| panic!("failed to write info data to {}", info_path));
                }
            }
            "parse" => {
                let path = matches.value_of("path").expect("path match failure");
                let (_, _, _, _, _, size, raw) = parse_params_filename(&path);

                if raw {
                    unimplemented!("`parse` command does not currently support raw params");
                }

                let file_info = if size.is_large() {
                    FileInfo::parse_large(&path)
                } else {
                    FileInfo::parse_small(&path)
                };

                println!("{:#?}", file_info);
            }
            "verify-g1" => {
                let path = matches.value_of("path").expect("path match failure");
                let (_, _, _, _, _, _, raw) = parse_params_filename(&path);

                assert!(
                    raw,
                    "found non-raw params, `verify-g1` is relevant only when verifying small-raw \
                    params"
                );

                let file = File::open(&path).expect("failed to open params file");
                let mut reader = BufReader::with_capacity(1024 * 1024, file);

                println!("starting deserialization");

                let start = Instant::now();
                let _params =
                    MPCSmall::read(&mut reader, raw, true).expect("mpc small read failure");

                println!(
                    "succesfully verified h and l G1 points, dt={}s",
                    start.elapsed().as_secs()
                );
            }
            _ => unreachable!(),
        }
    }
}
