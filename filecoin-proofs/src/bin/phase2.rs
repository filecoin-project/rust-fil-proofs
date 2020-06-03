/// A CLI program for running Phase2 of Filecoin's trusted-setup.
///
/// # Build
///
/// From the directory `rust-fil-proofs` run:
///
/// ```
/// $ RUSTFLAGS="-C target-cpu=native" cargo build --release -p filecoin-proofs --bin=phase2
/// ```
///
/// # Usage
///
/// ```
/// # Create initial params for a circuit using:
/// $ RUST_BACKTRACE=1 ./target/release/phase2 new \
///     <--porep, --epost, --fpost> \
///     [--poseidon (default), --sha-pedersen] \
///     <--2kib, --8mib, --512mib, --32gib, --64gib>
///
/// # Contribute randomness to the phase2 params for a circuit:
/// $ RUST_BACKTRACE=1 ./target/release/phase2 contribute <path to params file>
///
/// # Verify the transition from one phase2 params file to another:
/// $ RUST_BACKTRACE=1 ./target/release/phase2 verify \
///     --paths=<comma separated list of file paths to params> \
///     --contributions=<comma separated list of contribution digests>
///
/// # Run verification as a daemon - verify the parameters and contributions as they are written to
/// # the `rust-fil-proofs` directory:
/// $ RUST_BACKTRACE=1 ./target/release/phase2 verifyd
/// ```
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::process::Command;
use std::str::{self, FromStr};
use std::thread::sleep;
use std::time::{Duration, Instant};

use clap::{App, AppSettings, Arg, ArgGroup, SubCommand};
use filecoin_proofs::constants::*;
use filecoin_proofs::parameters::{
    setup_params, window_post_public_params, winning_post_public_params,
};
use filecoin_proofs::types::*;
use filecoin_proofs::with_shape;
use log::info;
use phase2::{verify_contribution, MPCParameters};
use rand::SeedableRng;
use simplelog::{self, CombinedLogger, LevelFilter, TermLogger, TerminalMode, WriteLogger};
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::hasher::Sha256Hasher;
use storage_proofs::merkle::MerkleTreeTrait;
use storage_proofs::porep::stacked::{StackedCircuit, StackedCompound, StackedDrg};
use storage_proofs::post::fallback::{FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound};

#[derive(Clone, Copy)]
enum Proof {
    Porep,
    WinningPost,
    WindowPost,
}

impl Display for Proof {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Proof::Porep => "PoRep",
            Proof::WinningPost => "WinningPoSt",
            Proof::WindowPost => "WindowPoSt",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy)]
enum Hasher {
    Poseidon,
    // ShaPedersen,
}

impl Display for Hasher {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Hasher::Poseidon => "Poseidon",
            // Hasher::ShaPedersen => "SHA-Pedersen",
        };
        write!(f, "{}", s)
    }
}

fn display_sector_size(sector_size: u64) -> String {
    match sector_size {
        SECTOR_SIZE_2_KIB => "2KiB".to_string(),
        SECTOR_SIZE_8_MIB => "8MiB".to_string(),
        SECTOR_SIZE_512_MIB => "512MiB".to_string(),
        SECTOR_SIZE_32_GIB => "32GiB".to_string(),
        SECTOR_SIZE_64_GIB => "64GiB".to_string(),
        _ => unreachable!(),
    }
}

fn get_head_commit() -> String {
    let output = Command::new("git")
        .args(&["rev-parse", "--short=7", "HEAD"])
        .output()
        .expect("failed to execute child process: `git rev-parse --short=7 HEAD`");

    str::from_utf8(&output.stdout).unwrap().trim().to_string()
}

fn params_filename(
    proof: Proof,
    hasher: Hasher,
    sector_size: u64,
    head: &str,
    param_number: usize,
) -> String {
    let mut filename = format!(
        "{}_{}_{}_{}_{}",
        proof,
        hasher,
        display_sector_size(sector_size),
        head,
        param_number
    );
    filename.make_ascii_lowercase();
    filename.replace("-", "_")
}

fn initial_params_filename(proof: Proof, hasher: Hasher, sector_size: u64) -> String {
    params_filename(proof, hasher, sector_size, &get_head_commit(), 0)
}

/// Parses a phase2 parameters filename `path` (e.g. "porep_poseidon_32gib_abcdef_0") to a tuple
/// containing the proof, hasher, sector-size, shortened head commit, and contribution number (e.g.
/// `(Proof::Porep, Hasher::Poseidon, SECTOR_SIZE_32_GIB, "abcdef1", 0)`).
fn parse_params_filename(path: &str) -> (Proof, Hasher, u64, String, usize) {
    let filename = path.rsplitn(2, '/').next().unwrap();
    let split: Vec<&str> = filename.split('_').collect();

    let proof = match split[0] {
        "porep" => Proof::Porep,
        "winning-post" => Proof::WinningPost,
        "window-post" => Proof::WindowPost,
        other => panic!("invalid proof id in filename: {}", other),
    };

    // TODO: this is broken if we enable SHA-Pedersen.
    let hasher = match split[1] {
        "poseidon" => Hasher::Poseidon,
        // "sha_pedersen" => Hasher::ShaPedersen,
        other => panic!("invalid hasher id in filename: {}", other),
    };

    let sector_size = match split[2] {
        "2kib" => SECTOR_SIZE_2_KIB,
        "8mib" => SECTOR_SIZE_8_MIB,
        "512mib" => SECTOR_SIZE_512_MIB,
        "32gib" => SECTOR_SIZE_32_GIB,
        "64gib" => SECTOR_SIZE_64_GIB,
        other => panic!("invalid sector-size id in filename: {}", other),
    };

    let head = split[3].to_string();

    let param_number = usize::from_str(split[4])
        .unwrap_or_else(|_| panic!("invalid param number in filename: {}", split[3]));

    (proof, hasher, sector_size, head, param_number)
}

fn blank_porep_poseidon_circuit<Tree: MerkleTreeTrait>(
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
/*
fn blank_fallback_post_sha_pedersen_circuit(sector_size: u64) -> ... {}
*/

/// Creates the first phase2 parameters for a circuit and writes them to a file.
fn create_initial_params<Tree: 'static + MerkleTreeTrait>(
    proof: Proof,
    hasher: Hasher,
    sector_size: u64,
) {
    let start_total = Instant::now();

    info!(
        "creating initial params for circuit: {} {} {} {}",
        proof,
        hasher,
        display_sector_size(sector_size),
        get_head_commit()
    );

    let params_path = initial_params_filename(proof, hasher, sector_size);
    let params_file = File::create(&params_path).unwrap();
    let mut params_writer = BufWriter::with_capacity(1024 * 1024, params_file);

    let dt_create_circuit: u64;
    let dt_create_params: u64;

    let params = match (proof, hasher) {
        (Proof::Porep, Hasher::Poseidon) => {
            let start = Instant::now();
            let circuit = blank_porep_poseidon_circuit::<Tree>(sector_size);
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = phase2::MPCParameters::new(circuit).unwrap();
            dt_create_params = start.elapsed().as_secs();
            params
        }
        /*
        (Proof::Porep, Hasher::ShaPedersen) => {
            let start = Instant::now();
            let circuit = blank_porep_sha_pedersen_circuit(sector_size);
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = phase2::MPCParameters::new(circuit).unwrap();
            dt_create_params = start.elapsed().as_secs();
            params
        }
        */
        (Proof::WinningPost, Hasher::Poseidon) => {
            let start = Instant::now();
            let circuit = blank_winning_post_poseidon_circuit::<Tree>(sector_size);
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = phase2::MPCParameters::new(circuit).unwrap();
            dt_create_params = start.elapsed().as_secs();
            params
        }
        (Proof::WindowPost, Hasher::Poseidon) => {
            let start = Instant::now();
            let circuit = blank_window_post_poseidon_circuit::<Tree>(sector_size);
            dt_create_circuit = start.elapsed().as_secs();
            let start = Instant::now();
            let params = phase2::MPCParameters::new(circuit).unwrap();
            dt_create_params = start.elapsed().as_secs();
            params
        } /*(Proof::FallbackPost, Hasher::ShaPedersen) => { ... }
           */
    };

    info!(
        "successfully created initial params for circuit, dt_create_circuit={}s, dt_create_params={}s",
        dt_create_circuit,
        dt_create_params
    );

    info!("writing initial params to file: {}", params_path);
    params.write(&mut params_writer).unwrap();

    info!(
        "successfully created initial params for circuit: {} {} {} {}, dt_total={}s",
        proof,
        hasher,
        display_sector_size(sector_size),
        get_head_commit(),
        start_total.elapsed().as_secs()
    );
}

/// Prompt the user to mash on their keyboard to gather entropy.
fn prompt_for_randomness() -> [u8; 32] {
    use dialoguer::{theme::ColorfulTheme, Password};

    let raw = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(
            "Please randomly press your keyboard for entropy (press Return/Enter when finished)",
        )
        .interact()
        .unwrap();

    let hashed = blake2b_simd::blake2b(raw.as_bytes());

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hashed.as_ref()[..32]);
    seed
}

/// Contributes entropy to the current phase2 parameters for a circuit, then writes the updated
/// parameters to a new file.
fn contribute_to_params(path_before: &str) {
    let start_total = Instant::now();

    let (proof, hasher, sector_size, head, param_number_before) =
        parse_params_filename(path_before);

    info!(
        "contributing randomness to params for circuit: {} {} {} {}",
        proof,
        hasher,
        display_sector_size(sector_size),
        head
    );

    assert_eq!(
        head,
        get_head_commit(),
        "cannot contribute to parameters using a different circuit version",
    );

    let seed = prompt_for_randomness();
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    info!("reading 'before' params from disk: {}", path_before);
    let file_before = File::open(path_before).unwrap();
    let mut params_reader = BufReader::with_capacity(1024 * 1024, file_before);
    let start = Instant::now();
    let mut params = phase2::MPCParameters::read(&mut params_reader, true).unwrap();
    info!(
        "successfully read 'before' params from disk, dt_read={}s",
        start.elapsed().as_secs()
    );

    info!("making contribution");
    let start = Instant::now();
    let contribution = params.contribute(&mut rng);
    info!(
        "successfully made contribution, contribution hash: {}, dt_contribute={}s",
        hex::encode(&contribution[..]),
        start.elapsed().as_secs()
    );

    let path_after = params_filename(proof, hasher, sector_size, &head, param_number_before + 1);
    info!("writing 'after' params to file: {}", path_after);
    let file_after = File::create(path_after).unwrap();
    let mut params_writer = BufWriter::with_capacity(1024 * 1024, file_after);
    params.write(&mut params_writer).unwrap();
    info!(
        "successfully made contribution, dt_total={}s",
        start_total.elapsed().as_secs()
    );
}

/// Verifies a sequence of parameter transitions against a sequence of corresponding contribution
/// hashes. For example, verifies that the first digest in `contribution_hashes` transitions the
/// first parameters file in `param_paths` to the second file, then verifies that the second
/// contribution hash transitions the second parameters file to the third file.
fn verify_param_transitions(param_paths: &[&str], contribution_hashes: &[[u8; 64]]) {
    let start_total = Instant::now();

    assert_eq!(
        param_paths.len() - 1,
        contribution_hashes.len(),
        "the number of contributions must be one less than the number of parameter files"
    );

    let mut next_params_before: Option<phase2::MPCParameters> = None;

    for (param_pair, provided_contribution_hash) in
        param_paths.windows(2).zip(contribution_hashes.iter())
    {
        let path_before = param_pair[0];
        let path_after = param_pair[1];

        info!(
            "verifying transition:\n\tparams: {} -> {}\n\tcontribution: {}",
            path_before,
            path_after,
            hex::encode(&provided_contribution_hash[..])
        );

        // If we are verifying the first contribution read both `path_before` and `path_after`
        // files. For every subsequent verification, move the previous loop's "after" params to this
        // loop's "before" params then read this loop's "after" params file. This will minimize the
        // number of expensive parameter file reads.
        let params_before = match next_params_before.take() {
            Some(params_before) => params_before,
            None => {
                info!("reading 'before' params from disk: {}", path_before);
                let file = File::open(path_before).unwrap();
                let mut reader = BufReader::with_capacity(1024 * 1024, file);
                let start = Instant::now();
                let params_before = phase2::MPCParameters::read(&mut reader, true).unwrap();
                info!(
                    "successfully read 'before' params from disk, dt_read={}s",
                    start.elapsed().as_secs()
                );
                params_before
            }
        };

        let params_after = {
            info!("reading 'after' params from disk: {}", path_after);
            let file = File::open(path_after).unwrap();
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            let start = Instant::now();
            let params_after = phase2::MPCParameters::read(&mut reader, true).unwrap();
            info!(
                "successfully read 'after' params from disk, dt_read={}s",
                start.elapsed().as_secs()
            );
            params_after
        };

        info!("verifying param transition");
        let start_verification = Instant::now();

        let calculated_contribution_hash =
            phase2::verify_contribution(&params_before, &params_after).expect("invalid transition");

        assert_eq!(
            &provided_contribution_hash[..],
            &calculated_contribution_hash[..],
            "provided contribution hash ({}) does not match calculated contribution hash ({})",
            hex::encode(&provided_contribution_hash[..]),
            hex::encode(&calculated_contribution_hash[..]),
        );

        info!(
            "successfully verified param transition, dt_verify={}s",
            start_verification.elapsed().as_secs()
        );

        next_params_before = Some(params_after);
    }

    info!(
        "successfully verified all param transitions, dt_total={}s",
        start_total.elapsed().as_secs()
    );
}

fn verify_param_transistions_daemon(proof: Proof, hasher: Hasher, sector_size: u64) {
    const SLEEP_SECS: u64 = 10;

    let head = get_head_commit();

    info!(
        "starting the verification daemon for the circuit: {} {} {} {}",
        proof,
        hasher,
        display_sector_size(sector_size),
        head
    );

    let mut next_before_params: Option<MPCParameters> = None;
    let mut next_before_filename: Option<String> = None;
    let mut param_number: usize = 0;

    loop {
        let (before_params, before_filename) = if next_before_params.is_some() {
            let before_params = next_before_params.take().unwrap();
            let before_filename = next_before_filename.take().unwrap();
            (before_params, before_filename)
        } else {
            let before_filename = params_filename(proof, hasher, sector_size, &head, param_number);
            let before_path = Path::new(&before_filename);
            if !before_path.exists() {
                info!("waiting for params file: {}", before_filename);
                while !before_path.exists() {
                    sleep(Duration::from_secs(SLEEP_SECS));
                }
            }
            info!("found file: {}", before_filename);
            info!("reading params file: {}", before_filename);
            let file = File::open(&before_path).unwrap();
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            let read_start = Instant::now();
            let before_params = MPCParameters::read(&mut reader, true).unwrap();
            info!(
                "successfully read params, dt_read={}s",
                read_start.elapsed().as_secs()
            );
            param_number += 1;
            (before_params, before_filename)
        };

        let after_filename = params_filename(proof, hasher, sector_size, &head, param_number);
        let after_path = Path::new(&after_filename);

        if !after_path.exists() {
            info!("waiting for params file: {}", after_filename);
            while !after_path.exists() {
                sleep(Duration::from_secs(SLEEP_SECS));
            }
        }
        info!("found file: {}", after_filename);

        let after_params = {
            info!("reading params file: {}", after_filename);
            let file = File::open(&after_path).unwrap();
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            let read_start = Instant::now();
            let params = MPCParameters::read(&mut reader, true).unwrap();
            info!(
                "successfully read params, dt_read={}s",
                read_start.elapsed().as_secs()
            );
            param_number += 1;
            params
        };

        let contribution_hash_filename = format!("{}_contribution", after_filename);
        let contribution_hash_path = Path::new(&contribution_hash_filename);

        if !contribution_hash_path.exists() {
            info!(
                "waiting for contribution hash file: {}",
                contribution_hash_filename
            );
            while !contribution_hash_path.exists() {
                sleep(Duration::from_secs(SLEEP_SECS));
            }
        }
        info!("found file: {}", contribution_hash_filename);

        let hex_str = fs::read_to_string(&contribution_hash_path)
            .expect("failed to read contribution hash file")
            .trim()
            .to_string();

        let provided_contribution_hash = {
            let mut arr = [0u8; 64];
            let vec = hex::decode(&hex_str).unwrap_or_else(|_| {
                panic!("contribution hash is not a valid hex string: {}", hex_str)
            });
            info!("parsed contribution hash");
            arr.copy_from_slice(&vec[..]);
            arr
        };

        info!(
            "verifying param transition:\n\t{} -> {}\n\t{}",
            before_filename, after_filename, hex_str
        );

        let start_verification = Instant::now();

        let calculated_contribution_hash =
            verify_contribution(&before_params, &after_params).expect("invalid transition");

        assert_eq!(
            &provided_contribution_hash[..],
            &calculated_contribution_hash[..],
            "provided contribution hash ({}) does not match calculated contribution hash ({})",
            hex_str,
            hex::encode(&calculated_contribution_hash[..]),
        );

        info!(
            "successfully verified param transition, dt_verify={}s\n",
            start_verification.elapsed().as_secs()
        );

        next_before_params = Some(after_params);
        next_before_filename = Some(after_filename);
    }
}

/// Creates the logger for the "new" CLI subcommand. Writes info logs to stdout, error logs to
/// stderr, and all logs to the file: `<proof>_<hasher>_<sector-size>_<head>_0.log`.
fn setup_new_logger(proof: Proof, hasher: Hasher, sector_size: u64) {
    let log_filename = format!(
        "{}.log",
        initial_params_filename(proof, hasher, sector_size)
    );

    let log_file = File::create(&log_filename)
        .unwrap_or_else(|_| panic!("failed to create log file: {}", log_filename));

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            simplelog::Config::default(),
            TerminalMode::Mixed,
        )
        .unwrap(),
        WriteLogger::new(LevelFilter::Info, simplelog::Config::default(), log_file),
    ])
    .expect("failed to setup logger");
}

/// Creates the logger for the "contribute" CLI subcommand. Writes info logs to stdout, error logs
/// to stderr, and all logs to the file:
/// `<proof>_<hasher>_<sector-size>_<head>_<param number containing contribution>.log`.
fn setup_contribute_logger(path_before: &str) {
    let (proof, hasher, sector_size, head, param_number_before) =
        parse_params_filename(path_before);

    let mut log_filename =
        params_filename(proof, hasher, sector_size, &head, param_number_before + 1);

    log_filename.push_str(".log");

    let log_file = File::create(&log_filename)
        .unwrap_or_else(|_| panic!("failed to create log file: {}", log_filename));

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            simplelog::Config::default(),
            TerminalMode::Mixed,
        )
        .unwrap(),
        WriteLogger::new(LevelFilter::Info, simplelog::Config::default(), log_file),
    ])
    .expect("failed to setup logger");
}

/// Creates the logger for the "contribute" CLI subcommand. Writes info logs to stdout, error logs
/// to stderr, and all logs to the file:
/// <proof>_<hasher>_<sector-size>_<head>_verify_<first param number>_<last param number>.log
fn setup_verify_logger(param_paths: &[&str]) {
    let (proof, hasher, sector_size, head, first_param_number) =
        parse_params_filename(param_paths.first().unwrap());

    let last_param_number = parse_params_filename(param_paths.last().unwrap()).4;

    let mut log_filename = format!(
        "{}_{}_{}_{}_verify_{}_{}.log",
        proof,
        hasher,
        display_sector_size(sector_size),
        head,
        first_param_number,
        last_param_number
    );
    log_filename.make_ascii_lowercase();
    let log_filename = log_filename.replace("-", "_");

    let log_file = File::create(&log_filename)
        .unwrap_or_else(|_| panic!("failed to create log file: {}", log_filename));

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            simplelog::Config::default(),
            TerminalMode::Mixed,
        )
        .unwrap(),
        WriteLogger::new(LevelFilter::Info, simplelog::Config::default(), log_file),
    ])
    .expect("failed to setup logger");
}

/// Setup the logger for the `verifyd` CLI subcommand. Writes info logs to stdout, error logs to
/// stderr, and all logs to the file: <proof>_<hasher>_<sector-size>_<head>_verifyd.log
fn setup_verifyd_logger(proof: Proof, hasher: Hasher, sector_size: u64) {
    let mut log_filename = format!(
        "{}_{}_{}_{}_verifyd.log",
        proof,
        hasher,
        display_sector_size(sector_size),
        &get_head_commit(),
    );
    log_filename.make_ascii_lowercase();
    let log_filename = log_filename.replace("-", "_");

    let log_file = File::create(&log_filename)
        .unwrap_or_else(|_| panic!("failed to create log file: {}", log_filename));

    CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            simplelog::Config::default(),
            TerminalMode::Mixed,
        )
        .unwrap(),
        WriteLogger::new(LevelFilter::Info, simplelog::Config::default(), log_file),
    ])
    .expect("failed to setup logger");
}

#[allow(clippy::cognitive_complexity)]
fn main() {
    let new_command = SubCommand::with_name("new")
        .about("Create parameters")
        .arg(
            Arg::with_name("porep")
                .long("porep")
                .help("Generate PoRep parameters"),
        )
        .arg(
            Arg::with_name("winning-post")
                .long("winning-post")
                .help("Generate WinningPoSt parameters"),
        )
        .arg(
            Arg::with_name("window-post")
                .long("window-post")
                .help("Generate WindowPoSt parameters"),
        )
        .group(
            ArgGroup::with_name("proof")
                .args(&["porep", "winning-post", "window-post"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("poseidon")
                .long("poseidon")
                .help("Use the Poseidon hash function for column commitments and Merkle trees"),
        )
        /*
        .arg(
            Arg::with_name("sha-pedersen")
                .long("sha-pedersen")
                .help("Use SHA256 for column commitments and Pedersen hash for Merkle trees"),
        )
        */
        .group(
            ArgGroup::with_name("hasher")
                .args(&["poseidon"])
                .required(false), /*
                                  .args(&["poseidon", "sha-pedersen"])
                                  .required(true)
                                  .multiple(false),
                                  */
        )
        .arg(
            Arg::with_name("2kib")
                .long("2kib")
                .help("Use circuits with 2KiB sector sizes"),
        )
        .arg(
            Arg::with_name("8mib")
                .long("8mib")
                .help("Use circuits with 16MiB sector sizes"),
        )
        .arg(
            Arg::with_name("512mib")
                .long("512mib")
                .help("Use circuits with 256MiB sector sizes"),
        )
        .arg(
            Arg::with_name("32gib")
                .long("32gib")
                .help("Use circuits with 32GiB sector sizes"),
        )
        .arg(
            Arg::with_name("64gib")
                .long("64gib")
                .help("Use circuits with 64GiB sector sizes"),
        )
        .group(
            ArgGroup::with_name("sector-size")
                .args(&["2kib", "8mib", "512mib", "32gib", "64gib"])
                .required(true)
                .multiple(false),
        );

    let contribute_command = SubCommand::with_name("contribute")
        .about("Contribute to parameters")
        .arg(
            Arg::with_name("path-before")
                .index(1)
                .required(true)
                .help("The path to the parameters file to read and contribute to"),
        );

    let verify_command = SubCommand::with_name("verify")
        .about("Verify that a set of contribution hashes correctly transition a set of params")
        .arg(
            Arg::with_name("paths")
                .long("paths")
                .required(true)
                .takes_value(true)
                .value_delimiter(",")
                .min_values(2)
                .help("Comma separated list (no whitespace between items) of paths to parameter files"),
        )
        .arg(
            Arg::with_name("contributions")
                .long("contributions")
                .required(true)
                .takes_value(true)
                .case_insensitive(true)
                .value_delimiter(",")
                .min_values(1)
                .help(
                    "An ordered (first to most recent) comma separated list of hex-encoded \
                    contribution hashes. There must be no whitespace in any of the digest strings \
                    or between any items in the list. Each digest must be 128 characters long \
                    (i.e. each digest hex string encodes 64 bytes), digest strings can use upper \
                    or lower case hex characters."
                ),
        );

    let verifyd_command = SubCommand::with_name("verifyd")
        .about("Run the param verification daemon")
        .arg(
            Arg::with_name("porep")
                .long("porep")
                .help("Generate PoRep parameters"),
        )
        .arg(
            Arg::with_name("winning-post")
                .long("winning-post")
                .help("Generate WinningPoSt parameters"),
        )
        .arg(
            Arg::with_name("window-post")
                .long("window-post")
                .help("Generate WindowPoSt parameters"),
        )
        .group(
            ArgGroup::with_name("proof")
                .args(&["porep", "winning-post", "window-post"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("poseidon")
                .long("poseidon")
                .help("Use the Poseidon hash function for column commitments and Merkle trees"),
        )
        /*
        .arg(
            Arg::with_name("sha-pedersen")
                .long("sha-pedersen")
                .help("Use SHA256 for column commitments and Pedersen hash for Merkle trees"),
        )
        */
        .group(
            ArgGroup::with_name("hasher")
                .args(&["poseidon"])
                .required(false), /*
                                  .args(&["poseidon", "sha-pedersen"])
                                  .required(true)
                                  .multiple(false),
                                  */
        )
        .arg(
            Arg::with_name("2kib")
                .long("2kib")
                .help("Use circuits with 2KiB sector sizes"),
        )
        .arg(
            Arg::with_name("8mib")
                .long("8mib")
                .help("Use circuits with 16MiB sector sizes"),
        )
        .arg(
            Arg::with_name("512mib")
                .long("512mib")
                .help("Use circuits with 256MiB sector sizes"),
        )
        .arg(
            Arg::with_name("32gib")
                .long("32gib")
                .help("Use circuits with 32GiB sector sizes"),
        )
        .arg(
            Arg::with_name("64gib")
                .long("64gib")
                .help("Use circuits with 64GiB sector sizes"),
        )
        .group(
            ArgGroup::with_name("sector-size")
                .args(&["2kib", "8mib", "512mib", "32gib", "64gib"])
                .required(true)
                .multiple(false),
        );

    let matches = App::new("phase2")
        .version("1.0")
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::SubcommandRequired)
        .subcommand(new_command)
        .subcommand(contribute_command)
        .subcommand(verify_command)
        .subcommand(verifyd_command)
        .get_matches();

    if let (subcommand, Some(matches)) = matches.subcommand() {
        match subcommand {
            "new" => {
                let proof = if matches.is_present("porep") {
                    Proof::Porep
                } else if matches.is_present("winning-post") {
                    Proof::WinningPost
                } else {
                    Proof::WindowPost
                };

                // Default to using Poseidon for the hasher.
                let hasher = Hasher::Poseidon;
                /*
                let hasher = if matches.is_present("sha-pedersen") {
                    Hasher::ShaPedersen
                } else {
                    Hasher::Poseidon
                };
                */

                let sector_size = if matches.is_present("2kib") {
                    SECTOR_SIZE_2_KIB
                } else if matches.is_present("8mib") {
                    SECTOR_SIZE_8_MIB
                } else if matches.is_present("512mib") {
                    SECTOR_SIZE_512_MIB
                } else if matches.is_present("32gib") {
                    SECTOR_SIZE_32_GIB
                } else {
                    SECTOR_SIZE_64_GIB
                };

                setup_new_logger(proof, hasher, sector_size);
                with_shape!(
                    sector_size,
                    create_initial_params,
                    proof,
                    hasher,
                    sector_size
                );
            }
            "contribute" => {
                let path_before = matches.value_of("path-before").unwrap();
                setup_contribute_logger(path_before);
                contribute_to_params(path_before);
            }
            "verify" => {
                let param_paths: Vec<&str> = matches.values_of("paths").unwrap().collect();

                let contribution_hashes: Vec<[u8; 64]> = matches
                    .values_of("contributions")
                    .unwrap()
                    .map(|hex_str| {
                        let mut digest_bytes_arr = [0u8; 64];
                        let digest_bytes_vec = hex::decode(hex_str).unwrap_or_else(|_| {
                            panic!("contribution hash is not a valid hex string: {}", hex_str)
                        });
                        digest_bytes_arr.copy_from_slice(&digest_bytes_vec[..]);
                        digest_bytes_arr
                    })
                    .collect();

                setup_verify_logger(&param_paths);
                verify_param_transitions(&param_paths, &contribution_hashes);
            }
            "verifyd" => {
                let proof = if matches.is_present("porep") {
                    Proof::Porep
                } else if matches.is_present("winning-post") {
                    Proof::WinningPost
                } else {
                    Proof::WindowPost
                };

                // Default to using Poseidon for the hasher.
                let hasher = Hasher::Poseidon;
                /*
                let hasher = if matches.is_present("sha-pedersen") {
                    Hasher::ShaPedersen
                } else {
                    Hasher::Poseidon
                };
                */

                let sector_size = if matches.is_present("2kib") {
                    SECTOR_SIZE_2_KIB
                } else if matches.is_present("8mib") {
                    SECTOR_SIZE_8_MIB
                } else if matches.is_present("512mib") {
                    SECTOR_SIZE_512_MIB
                } else if matches.is_present("32gib") {
                    SECTOR_SIZE_32_GIB
                } else {
                    SECTOR_SIZE_64_GIB
                };

                setup_verifyd_logger(proof, hasher, sector_size);
                verify_param_transistions_daemon(proof, hasher, sector_size);
            }
            _ => unreachable!(),
        }
    }
}
