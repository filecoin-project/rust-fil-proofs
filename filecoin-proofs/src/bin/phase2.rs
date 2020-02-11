/// # Build
///
/// ```
/// # From the directory `rust-fil-proofs/filecoin-proofs`:
/// $ cargo build --release --bin=phase2
/// ```
///
/// # Usage
///
/// ```
/// $ ./target/release/phase2 new \
///     {--porep, --post} \
///     {--poseidon, --sha-pedersen} \
///     --sector-size=<1kib, 16mib, 256mib, 1gib, 32gib, 64gib> \
///     --path=<file path to write params>
///
/// $ ./target/release/phase2 contribute \
///     {--porep, --post} \
///     {--poseidon, --sha-pedersen} \
///     --sector-size=<1kib, 16mib, 256mib, 1gib, 32gib, 64gib> \
///     --path-before=<file path to read params> \
///     --path-after=<file path to write params>
///
/// $ ./target/release/phase2 verify \
///     --paths=<comma separated list of file paths to params> \
///     --contributions=<comma separated list of contribution digests>
/// ```
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::atomic::Ordering;

use clap::{App, AppSettings, Arg, ArgGroup, SubCommand};
use filecoin_proofs::constants::{
    DefaultPieceHasher, DefaultTreeHasher, DEFAULT_POREP_PROOF_PARTITIONS, POST_CHALLENGED_NODES,
    POST_CHALLENGE_COUNT, SECTOR_SIZE_16_MIB, SECTOR_SIZE_1_GIB, SECTOR_SIZE_256_MIB,
    SECTOR_SIZE_32_GIB, /*SECTOR_SIZE_64_GIG,*/ SECTOR_SIZE_ONE_KIB,
};
use filecoin_proofs::parameters::{post_public_params, setup_params};
use filecoin_proofs::types::*;
use log::info;
use paired::bls12_381::Bls12;
use phase21 as phase2;
use rand::SeedableRng;
use storage_proofs::circuit::election_post::{ElectionPoStCircuit, ElectionPoStCompound};
use storage_proofs::circuit::stacked::{StackedCircuit, StackedCompound};
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::election_post::ElectionPoSt;
use storage_proofs::stacked::StackedDrg;

enum Proof {
    Porep,
    Post,
}

impl Display for Proof {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Proof::Porep => "PoRep",
            Proof::Post => "PoST",
        };
        write!(f, "{}", s)
    }
}

enum Hasher {
    Poseidon,
    ShaPedersen,
}

impl Display for Hasher {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let s = match self {
            Hasher::Poseidon => "Poseidon",
            Hasher::ShaPedersen => "SHA-Pedersen",
        };
        write!(f, "{}", s)
    }
}

fn display_sector_size(sector_size: u64) -> String {
    match sector_size {
        SECTOR_SIZE_ONE_KIB => "1KiB".to_string(),
        SECTOR_SIZE_16_MIB => "16MiB".to_string(),
        SECTOR_SIZE_256_MIB => "256MiB".to_string(),
        SECTOR_SIZE_1_GIB => "1GiB".to_string(),
        SECTOR_SIZE_32_GIB => "32GiB".to_string(),
        // SECTOR_SIZE_64_GIB => "64GiB".to_string(),
        _ => unreachable!(),
    }
}

/*
fn blank_porep_poseidon_circuit(
    sector_size: u64,
) -> StackedCircuit<'static, Bls12, PoseidonHasher, Sha256Hasher> {
    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(DEFAULT_POREP_PROOF_PARTITIONS.load(Ordering::Relaxed)),
    };

    let setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )
        .unwrap(),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let public_params =
        <StackedCompound as CompoundProof<_, StackedDrg<PoseidonHasher, Sha256Hasher>, _>>::setup(
            &setup_params,
        )
        .unwrap();

    <StackedCompound as CompoundProof<
        _,
        StackedDrg<PoseidonHasher, Sha256Hasher>,
        _,
    >>::blank_circuit(&public_params.vanilla_params)
}
*/

fn blank_porep_sha_pedersen_circuit(
    sector_size: u64,
) -> StackedCircuit<'static, Bls12, PedersenHasher, Sha256Hasher> {
    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(DEFAULT_POREP_PROOF_PARTITIONS.load(Ordering::Relaxed)),
    };

    let setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )
        .unwrap(),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let public_params =
        <StackedCompound as CompoundProof<_, StackedDrg<PedersenHasher, Sha256Hasher>, _>>::setup(
            &setup_params,
        )
        .unwrap();

    <StackedCompound as CompoundProof<
        _,
        StackedDrg<PedersenHasher, Sha256Hasher>,
        _,
    >>::blank_circuit(&public_params.vanilla_params)
}

/*
fn blank_post_poseidon_circuit(
    sector_size: u64,
) -> ElectionPoStCircuit<'static, Bls12, PoseidonHasher> {
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: POST_CHALLENGE_COUNT,
        challenged_nodes: POST_CHALLENGED_NODES,
    };

    let public_params = post_public_params(post_config).unwrap();

    <ElectionPoStCompound<PoseidonHasher> as CompoundProof<
        Bls12,
        ElectionPoSt<PoseidonHasher>,
        ElectionPoStCircuit<Bls12, PoseidonHasher>,
    >>::blank_circuit(&public_params)
}
*/

fn blank_post_sha_pedersen_circuit(
    sector_size: u64,
) -> ElectionPoStCircuit<'static, Bls12, PedersenHasher> {
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: POST_CHALLENGE_COUNT,
        challenged_nodes: POST_CHALLENGED_NODES,
    };

    let public_params = post_public_params(post_config).unwrap();

    <ElectionPoStCompound<PedersenHasher> as CompoundProof<
        Bls12,
        ElectionPoSt<PedersenHasher>,
        ElectionPoStCircuit<Bls12, PedersenHasher>,
    >>::blank_circuit(&public_params)
}

fn create_initial_params(proof: Proof, hasher: Hasher, sector_size: u64, params_path: &str) {
    info!(
        "creating new params for circuit: {} {} {}",
        proof,
        hasher,
        display_sector_size(sector_size)
    );

    let params_file = File::create(params_path).unwrap();
    let mut params_writer = BufWriter::with_capacity(1024 * 1024, params_file);

    let params = match (proof, hasher) {
        /*
        (Proof::Porep, Hasher::Poseidon) => {
            let circuit = blank_porep_poseidon_circuit(sector_size);
            phase2::MPCParameters::new(circuit).unwrap()
        }
        */
        (Proof::Porep, Hasher::ShaPedersen) => {
            let circuit = blank_porep_sha_pedersen_circuit(sector_size);
            phase2::MPCParameters::new(circuit).unwrap()
        }
        /*
        (Proof::Post, Hasher::Poseidon) => {
            let circuit = blank_post_poseidon_circuit(sector_size);
            phase2::MPCParameters::new(circuit).unwrap()
        }
        */
        (Proof::Post, Hasher::ShaPedersen) => {
            let circuit = blank_post_sha_pedersen_circuit(sector_size);
            phase2::MPCParameters::new(circuit).unwrap()
        }
    };
    info!("successfully created params for circuit");

    info!("writing params to file: {}", params_path);
    params.write(&mut params_writer).unwrap();

    info!(
        "finished creating params for circuit: {} {} {}",
        proof,
        hasher,
        display_sector_size(sector_size)
    );
}

fn prompt_for_randomness() -> [u8; 32] {
    use dialoguer::{theme::ColorfulTheme, PasswordInput};

    let raw = PasswordInput::with_theme(&ColorfulTheme::default())
        .with_prompt("Please enter your randomness")
        .interact()
        .unwrap();

    let hashed = blake2b_simd::blake2b(raw.as_bytes());

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hashed.as_ref()[..32]);
    seed
}

fn contribute_to_params(
    proof: Proof,
    hasher: Hasher,
    sector_size: u64,
    params_path_before: &str,
    params_path_after: &str,
) {
    info!(
        "contributing randomness to params for circuit: {} {} {}",
        proof,
        hasher,
        display_sector_size(sector_size)
    );

    let params_file_before = File::open(params_path_before).unwrap();
    let mut params_reader = BufReader::with_capacity(1024 * 1024, params_file_before);

    info!("reading params from disk: {}", params_path_before);
    let mut params = phase2::MPCParameters::read(&mut params_reader, true).unwrap();

    let seed = prompt_for_randomness();
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    info!("making contribution");
    let contribution = params.contribute(&mut rng);
    info!("contribution hash: {}", hex::encode(&contribution[..]));

    // Do a quick verification to make sure that the new params that we write to disk contain our
    // contribution.
    info!("verifying contribution and new parameters");

    let all_contributions = match (proof, hasher) {
        /*
        (Proof::Porep, Hasher::Poseidon) => {
            let circuit = blank_porep_poseidon_circuit(sector_size);
            params.verify(circuit).expect("new parameters are invalid")
        }
        */
        (Proof::Porep, Hasher::ShaPedersen) => {
            let circuit = blank_porep_sha_pedersen_circuit(sector_size);
            params.verify(circuit).expect("new parameters are invalid")
        }
        /*
        (Proof::Post, Hasher::Poseidon) => {
            let circuit = blank_post_poseidon_circuit(sector_size);
            params.verify(circuit).expect("new parameters are invalid")
        }
        */
        (Proof::Post, Hasher::ShaPedersen) => {
            let circuit = blank_post_sha_pedersen_circuit(sector_size);
            params.verify(circuit).expect("new parameters are invalid")
        }
    };

    assert!(
        phase2::contains_contribution(&all_contributions, &contribution),
        "new parameters do not contain contribution"
    );

    info!("contribution and new parameters have been verified");

    // Write the new params which contain the participant's contribution to disk.
    info!("writing new params to disk: {}", params_path_after);
    let params_file_after = File::create(params_path_after).unwrap();
    let mut params_writer = BufWriter::with_capacity(1024 * 1024, params_file);
    params.write(&mut params_writer).unwrap();
    info!("finished writing new params to disk");
    info!("successfully made contribution");
}

fn verify_param_transitions(param_paths: &[&str], contribution_hashes: &[&[u8; 64]]) {
    assert_eq!(
        param_paths.len(),
        contribution_hashes.len() - 1,
        "the number of contributions must be one less than the number of parameter files"
    );

    for ((i, param_pair), expected_contribution_hash) in param_paths
        .windows(2)
        .enumerate()
        .zip(contribution_hashes.iter())
    {
        let path_before = param_pair[0];
        let path_after = param_pair[1];

        info!(
            "verifying transition #{}: {} -> {}, with contribution: {:?}",
            i + 1,
            path_before,
            path_after,
            &expected_contribution_hash[..]
        );

        let params_before = {
            info!("reading 'before contribution' params from disk");
            let file = File::open(path_before).unwrap();
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            phase2::MPCParameters::read(&mut reader, true).unwrap()
        };

        let params_after = {
            info!("reading 'after contribution' params from disk");
            let file = File::open(path_after).unwrap();
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            phase2::MPCParameters::read(&mut reader, true).unwrap()
        };

        let calculated_contribution_hash =
            phase2::verify_contribution(&params_before, &params_after).expect("invalid transition");

        assert_eq!(
            &calculated_contribution_hash[..],
            &expected_contribution_hash[..],
            "contribution hashes do not match"
        );
    }
}

fn main() {
    simplelog::SimpleLogger::init(log::LevelFilter::Info, simplelog::Config::default())
        .expect("failed to init logger");

    let new_command = SubCommand::with_name("new")
        .about("Create parameters")
        .arg(
            Arg::with_name("porep")
                .long("porep")
                .help("Generate PoRep parameters"),
        )
        .arg(
            Arg::with_name("post")
                .long("post")
                .help("Generate PoSt parameters"),
        )
        .group(
            ArgGroup::with_name("proof")
                .args(&["porep", "post"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("poseidon")
                .long("poseidon")
                .help("Use the Poseidon hash function for column commitments and Merkle trees"),
        )
        .arg(
            Arg::with_name("sha-pedersen")
                .long("sha-pedersen")
                .help("Use SHA256 for column commitments and Pedersen hash for Merkle trees"),
        )
        .group(
            ArgGroup::with_name("hasher")
                .args(&["poseidon", "sha-pedersen"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("sector-size")
                .long("sector-size")
                .takes_value(true)
                .case_insensitive(true)
                .possible_values(&["1KiB", "16MiB", "256MiB", "1GiB", "32GiB"])
                // .default_value("1KiB")
                .help("The proof's sector size"),
        )
        .arg(
            Arg::with_name("path")
                .long("path")
                .required(true)
                .takes_value(true)
                .help("Path to where the initial parameters file should be written"),
        );

    let contribute_command = SubCommand::with_name("contribute")
        .about("Contribute to parameters")
        .arg(
            Arg::with_name("porep")
                .long("porep")
                .help("Contribute to the PoRep parameters"),
        )
        .arg(
            Arg::with_name("post")
                .long("post")
                .help("Contribute to the PoSt parameters"),
        )
        .group(
            ArgGroup::with_name("proof")
                .args(&["porep", "post"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("poseidon")
                .long("poseidon")
                .help("Use the Poseidon hash function for column commitments and Merkle trees"),
        )
        .arg(
            Arg::with_name("sha-pedersen")
                .long("sha-pedersen")
                .help("Use SHA256 for column commitments and Pedersen hash for Merkle trees"),
        )
        .group(
            ArgGroup::with_name("hasher")
                .args(&["poseidon", "sha-pedersen"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("sector-size")
                .long("sector-size")
                .takes_value(true)
                .case_insensitive(true)
                .possible_values(&["1KiB", "16MiB", "256MiB", "1GiB", "32GiB"])
                // .default_value("1KiB")
                .help("The proof's sector size"),
        )
        .arg(
            Arg::with_name("path-before")
                .long("path-before")
                .required(true)
                .takes_value(true)
                .help("Path to parameters file to read"),
        )
        .arg(
            Arg::with_name("path-after")
                .long("path-after")
                .required(true)
                .takes_value(true)
                .help("Path to parameters file to write to"),
        );

    let verify_command = SubCommand::with_name("verify")
        .about("Verify that a set of contributions match the provided parameters")
        .arg(
            Arg::with_name("paths")
                .long("paths")
                .required(true)
                .takes_value(true)
                .value_delimiter(",")
                .min_values(2)
                .help("Comma separated list (no whitespace between items) of paths to parameters files"),
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
                    "An ordered (earliest to most recent) comma separated list of hex-encoded \
                    contribution hashes. There must be no whitespace in any of the digest strings \
                    or between any items in the list, each digest must be 128 characters long \
                    (i.e. each digest hex string encodes 64 bytes), digest strings can use upper \
                    or lower case hex characters."
                ),
        );

    let matches = App::new("phase2")
        .version("0.1")
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::SubcommandRequired)
        .subcommand(new_command)
        .subcommand(contribute_command)
        .subcommand(verify_command)
        .get_matches();

    // If we've made it to this point without the CLI parser panicing, the following expression will
    // always destructure.
    if let (subcommand, Some(matches)) = matches.subcommand() {
        match subcommand {
            "new" => {
                let params_path = matches.value_of("path").unwrap();

                let proof = if matches.is_present("porep") {
                    Proof::Porep
                } else {
                    Proof::Post
                };

                let hasher = if matches.is_present("poseidon") {
                    Hasher::Poseidon
                } else {
                    Hasher::ShaPedersen
                };

                let sector_size: u64 = matches
                    .value_of("sector-size")
                    .map(|s| match s.to_lowercase().as_ref() {
                        "1kib" => SECTOR_SIZE_ONE_KIB,
                        "16mib" => SECTOR_SIZE_16_MIB,
                        "256mib" => SECTOR_SIZE_256_MIB,
                        "1gib" => SECTOR_SIZE_1_GIB,
                        "32gib" => SECTOR_SIZE_32_GIB,
                        // "64gib" => SECTOR_SIZE_64_GIB,
                        _ => unreachable!(),
                    })
                    .unwrap();

                create_initial_params(proof, hasher, sector_size, params_path);
            }
            "contribute" => {
                let path_before = matches.value_of("path-before").unwrap();
                let path_after = matches.value_of("path-after").unwrap();

                let proof = if matches.is_present("porep") {
                    Proof::Porep
                } else {
                    Proof::Post
                };

                let hasher = if matches.is_present("poseidon") {
                    Hasher::Poseidon
                } else {
                    Hasher::ShaPedersen
                };

                let sector_size: u64 = matches
                    .value_of("sector-size")
                    .map(|s| match s.to_lowercase().as_ref() {
                        "1kib" => SECTOR_SIZE_ONE_KIB,
                        "16mib" => SECTOR_SIZE_16_MIB,
                        "256mib" => SECTOR_SIZE_256_MIB,
                        "1gib" => SECTOR_SIZE_1_GIB,
                        "32gib" => SECTOR_SIZE_32_GIB,
                        // "64gib" => SECTOR_SIZE_64_GIB,
                        _ => unreachable!(),
                    })
                    .unwrap();

                contribute_to_params(proof, hasher, sector_size, path_before, path_after);
            }
            "verify" => {
                let param_paths: Vec<&str> = matches.values_of("paths").unwrap().collect();

                let contribution_hashes: Vec<[u8; 64]> = matches
                    .values_of("contributions")
                    .unwrap()
                    .map(|hex_str| {
                        let mut digest_bytes_arr = [0u8; 64];
                        let digest_bytes_vec = hex::decode(hex_str).expect(&format!(
                            "passed in contribution hash as an invalid hex string: {}",
                            hex_str
                        ));
                        digest_bytes_arr.copy_from_slice(&digest_bytes_vec[..]);
                        digest_bytes_arr
                    })
                    .collect();

                verify_params_match_contributions(&param_paths, &contribution_hashes);
            }
            _ => unreachable!(),
        }
    }
}

/*
fn get_porep_circuit(
    sector_size: u64,
) -> StackedCircuit<'static, Bls12, DefaultTreeHasher, DefaultPieceHasher> {
    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(DEFAULT_POREP_PROOF_PARTITIONS.load(Ordering::Relaxed)),
    };

    let setup_params = compound_proof::SetupParams {
        vanilla_params: setup_params(
            PaddedBytesAmount::from(porep_config),
            usize::from(PoRepProofPartitions::from(porep_config)),
        )
        .unwrap(),
        partitions: Some(usize::from(PoRepProofPartitions::from(porep_config))),
    };

    let public_params = <StackedCompound as CompoundProof<
        _,
        StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
        _,
    >>::setup(&setup_params)
    .expect("setup failed");

    <StackedCompound as CompoundProof<
        _,
        StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
        _,
    >>::blank_circuit(&public_params.vanilla_params)
}

fn get_post_circuit(sector_size: u64) -> ElectionPoStCircuit<'static, Bls12, DefaultTreeHasher> {
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: POST_CHALLENGE_COUNT,
        challenged_nodes: POST_CHALLENGED_NODES,
    };

    let public_params = post_public_params(post_config).unwrap();

    <ElectionPoStCompound<DefaultTreeHasher> as CompoundProof<
        Bls12,
        ElectionPoSt<DefaultTreeHasher>,
        ElectionPoStCircuit<Bls12, DefaultTreeHasher>,
    >>::blank_circuit(&public_params)
}

fn initial_setup_porep(sector_size: u64, params_path: &str) {
    let params = File::create(params_path).unwrap();
    let mut params = BufWriter::with_capacity(1024 * 1024, params);

    // Generate params for PoRep
    info!("Creating params for PoRep");
    phase2::MPCParameters::new(get_porep_circuit(sector_size))
        .unwrap()
        .write(&mut params)
        .unwrap();
    info!("successfully created params");
}

fn initial_setup_post(sector_size: u64, params_path: &str) {
    let params = File::create(params_path).unwrap();
    let mut params = BufWriter::with_capacity(1024 * 1024, params);

    // Generate params for PoRep
    info!("Creating params for PoSt");
    phase2::MPCParameters::new(get_post_circuit(sector_size))
        .unwrap()
        .write(&mut params)
        .unwrap();
    info!("successfully created params");
}

fn contribute_porep(sector_size: u64, params_path_before: &str, params_path_after: &str) {
    info!("Creating contribution for PoRep");
    let params_file = File::open(params_path_before).unwrap();
    let mut params_reader = BufReader::with_capacity(1024 * 1024, params_file);

    info!("reading params from disk");
    let mut params = phase2::MPCParameters::read(&mut params_reader, true).unwrap();

    let seed = prompt_for_randomness();
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    let contribution = params.contribute(&mut rng);
    info!("contribution hash: {}", hex::encode(&contribution[..]));

    // Do a quick verification to make sure that the new params that we write to disk contain our
    // contribution.
    info!("verifying contribution");
    let all_contributions = params
        .verify(get_porep_circuit(sector_size))
        .expect("invalid parameteres");
    assert!(
        phase2::contains_contribution(&all_contributions, &contribution),
        "Invalid contribution"
    );
    info!("contribution has been verified");

    // Write the params without contribution to disk.
    info!("writing new params to disk");
    let params_file = File::create(params_path_after).unwrap();
    let mut params_writer = BufWriter::with_capacity(1024 * 1024, params_file);
    params.write(&mut params_writer).unwrap();
    info!("finished writing new params to disk");
    info!("contribution success");
}

fn contribute_post(sector_size: u64, params_path_before: &str, params_path_after: &str) {
    info!("Creating contribution for PoSt");
    let params_file = File::open(params_path_before).unwrap();
    let mut params_reader = BufReader::with_capacity(1024 * 1024, params_file);

    info!("reading params from disk");
    let mut params = phase2::MPCParameters::read(&mut params_reader, true).unwrap();

    let seed = prompt_for_randomness();
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    let contribution = params.contribute(&mut rng);
    info!("contribution hash: {}", hex::encode(&contribution[..]));

    // Do a quick verification to make sure that the new params that we write to disk contain our
    // contribution.
    info!("verifying contribution");
    let all_contributions = params
        .verify(get_porep_circuit(sector_size))
        .expect("params read from file are not valid for PoRep circuit");
    assert!(
        phase2::contains_contribution(&all_contributions, &contribution),
        "Invalid contribution"
    );
    info!("contribution has been verified");

    // Write the params with out contribution to disk.
    info!("writing new params to disk");
    let params_file = File::create(params_path_after).unwrap();
    let mut params_writer = BufWriter::with_capacity(1024 * 1024, params_file);
    params.write(&mut params_writer).unwrap();
    info!("finished writing new params to disk");
    info!("contribution success");
}

fn prompt_for_randomness() -> [u8; 32] {
    use dialoguer::{theme::ColorfulTheme, PasswordInput};

    let raw = PasswordInput::with_theme(&ColorfulTheme::default())
        .with_prompt("Please enter your randomness")
        .interact()
        .unwrap();

    let hashed = blake2b_simd::blake2b(raw.as_bytes());

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hashed.as_ref()[..32]);
    seed
}

fn verify_params_match_contributions(param_paths: &[&str], contribution_hashes: &[[u8; 64]]) {
    assert_eq!(
        param_paths.len(),
        contribution_hashes.len() - 1,
        "the number of contributions must be one less than the number of parameter files"
    );

    let mut contribution_hashes = contribution_hashes.iter();

    for (contribution_index, param_pair) in param_paths.windows(2).enumerate() {
        info!("verifying contribution {}", contribution_index);

        let params_before = {
            info!("reading 'before contribution' params from disk");
            let path = param_pair[0];
            let file = File::open(path).unwrap();
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            phase2::MPCParameters::read(&mut reader, true).unwrap()
        };

        let params_after = {
            info!("reading 'after contribution' params from disk");
            let path = param_pair[1];
            let file = File::open(path).unwrap();
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            phase2::MPCParameters::read(&mut reader, true).unwrap()
        };

        let calculated_contribution_hash =
            phase2::verify_contribution(&params_before, &params_after)
                .expect("invalid contribution");

        let supplied_contribution_hash = contribution_hashes.next().unwrap();

        assert_eq!(
            &calculated_contribution_hash[..],
            &supplied_contribution_hash[..],
            "contribution hashes do not match"
        );
    }
}

fn main() {
    simplelog::SimpleLogger::init(log::LevelFilter::Info, simplelog::Config::default())
        .expect("failed to init logger");

    let new_command = SubCommand::with_name("new")
        .about("Create parameters")
        .arg(
            Arg::with_name("porep")
                .long("porep")
                .help("Generate PoRep parameters"),
        )
        .arg(
            Arg::with_name("post")
                .long("post")
                .help("Generate PoSt parameters"),
        )
        .group(
            ArgGroup::with_name("proof")
                .args(&["porep", "post"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("poseidon")
                .long("poseidon")
                .help("Use the Poseidon hash function for column commitments and Merkle trees"),
        )
        .arg(
            Arg::with_name("sha-pedersen")
                .long("sha-pedersen")
                .help("Use SHA256 for column commitments and Pedersen hash for Merkle trees"),
        )
        .group(
            ArgGroup::with_name("hasher")
                .args(&["poseidon", "sha-pedersen"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("sector-size")
                .long("sector-size")
                .takes_value(true)
                .case_insensitive(true)
                .possible_values(&["1KiB", "16MiB", "256MiB", "1GiB", "32GiB"])
                .default_value("1KiB")
                .help("The proof's sector size"),
        )
        .arg(
            Arg::with_name("parameters")
                .long("parameters")
                .required(true)
                .takes_value(true)
                .help("Path to where the initial parameters file should be written"),
        );

    let contribute_command = SubCommand::with_name("contribute")
        .about("Contribute to parameters")
        .arg(
            Arg::with_name("porep")
                .long("porep")
                .help("Contribute to the PoRep parameters"),
        )
        .arg(
            Arg::with_name("post")
                .long("post")
                .help("Contribute to the PoSt parameters"),
        )
        .group(
            ArgGroup::with_name("proof")
                .args(&["porep", "post"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("poseidon")
                .long("poseidon")
                .help("Use the Poseidon hash function for column commitments and Merkle trees"),
        )
        .arg(
            Arg::with_name("sha-pedersen")
                .long("sha-pedersen")
                .help("Use SHA256 for column commitments and Pedersen hash for Merkle trees"),
        )
        .group(
            ArgGroup::with_name("hasher")
                .args(&["poseidon", "sha-pedersen"])
                .required(true)
                .multiple(false),
        )
        .arg(
            Arg::with_name("sector-size")
                .long("sector-size")
                .takes_value(true)
                .case_insensitive(true)
                .possible_values(&["1KiB", "16MiB", "256MiB", "1GiB", "32GiB"])
                .default_value("1KiB")
                .help("The proof's sector size"),
        )
        .arg(
            Arg::with_name("parameters-before")
                .long("parameters-before")
                .required(true)
                .takes_value(true)
                .help("Path to parameters file to read"),
        )
        .arg(
            Arg::with_name("parameters-after")
                .long("parameters-after")
                .required(true)
                .takes_value(true)
                .help("Path to parameters file to write to"),
        );

    let verify_command = SubCommand::with_name("verify")
        .about("Verify that a set of contributions match the provided parameters")
        .arg(
            Arg::with_name("parameters")
                .long("parameters")
                .required(true)
                .takes_value(true)
                .value_delimiter(",")
                .min_values(2)
                .help("Comma separated list (no whitespace between items) of paths to parameters files"),
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
                    "An ordered (earliest to most recent) comma separated list of hex-encoded \
                    contribution hashes. There must be no whitespace in any of the digest strings \
                    or between any items in the list, each digest must be 128 characters long \
                    (i.e. each digest hex string encodes 64 bytes), digest strings can use upper \
                    or lower case hex characters."
                ),
        );

    let matches = App::new("phase2")
        .version("0.1")
        .setting(AppSettings::ArgRequiredElseHelp)
        .setting(AppSettings::SubcommandRequired)
        .subcommand(new_command)
        .subcommand(contribute_command)
        .subcommand(verify_command)
        .get_matches();

    // If we've made it to this point without the CLI parser panicing, the following expression will
    // always destructure.
    if let (subcommand, Some(matches)) = matches.subcommand() {
        match subcommand {
            "new" => {
                let params_path = matches.value_of("parameters").unwrap();

                let sector_size: u64 = matches
                    .value_of("sector-size")
                    .map(|s| match s.to_lowercase().as_ref() {
                        "1kib" => SECTOR_SIZE_ONE_KIB,
                        "16mib" => SECTOR_SIZE_16_MIB,
                        "256mib" => SECTOR_SIZE_256_MIB,
                        "1gib" => SECTOR_SIZE_1_GIB,
                        "32gib" => SECTOR_SIZE_32_GIB,
                        _ => unreachable!(),
                    })
                    .unwrap();

                if matches.is_present("porep") {
                    initial_setup_porep(sector_size, params_path);
                } else {
                    initial_setup_post(sector_size, params_path);
                }
            }
            "contribute" => {
                let params_path_before = matches.value_of("parameters-before").unwrap();
                let params_path_after = matches.value_of("parameters-after").unwrap();

                let sector_size: u64 = matches
                    .value_of("sector-size")
                    .map(|s| match s.to_lowercase().as_ref() {
                        "1kib" => SECTOR_SIZE_ONE_KIB,
                        "16mib" => SECTOR_SIZE_16_MIB,
                        "256mib" => SECTOR_SIZE_256_MIB,
                        "1gib" => SECTOR_SIZE_1_GIB,
                        "32gib" => SECTOR_SIZE_32_GIB,
                        _ => unreachable!(),
                    })
                    .unwrap();

                if matches.is_present("porep") {
                    contribute_porep(sector_size, params_path_before, params_path_after);
                } else {
                    contribute_post(sector_size, params_path_before, params_path_after);
                }
            }
            "verify" => {
                let param_paths: Vec<&str> = matches.values_of("parameters").unwrap().collect();

                let contribution_hashes: Vec<[u8; 64]> = matches
                    .values_of("contributions")
                    .unwrap()
                    .map(|hex_str| {
                        let mut digest_bytes_arr = [0u8; 64];
                        let digest_bytes_vec = hex::decode(hex_str).expect(&format!(
                            "passed in contribution hash as an invalid hex string: {}",
                            hex_str
                        ));
                        digest_bytes_arr.copy_from_slice(&digest_bytes_vec[..]);
                        digest_bytes_arr
                    })
                    .collect();

                verify_params_match_contributions(&param_paths, &contribution_hashes);
            }
            _ => unreachable!(),
        }
    }
}
*/
