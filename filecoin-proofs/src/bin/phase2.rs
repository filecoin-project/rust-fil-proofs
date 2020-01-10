use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::atomic::Ordering;

use clap::{value_t, App, AppSettings, Arg, SubCommand};
use filecoin_proofs::constants::{
    DefaultPieceHasher, DefaultTreeHasher, DEFAULT_POREP_PROOF_PARTITIONS, POST_CHALLENGED_NODES,
    POST_CHALLENGE_COUNT, SECTOR_SIZE_16_MIB, SECTOR_SIZE_1_GIB, SECTOR_SIZE_256_MIB,
    SECTOR_SIZE_32_GIB, SECTOR_SIZE_ONE_KIB,
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
}

fn contribute_porep(sector_size: u64, params_path: &str) {
    info!("Creating contribution for PoRep");
    let params = File::create(params_path).unwrap();
    let mut params_reader = BufReader::with_capacity(1024 * 1024, params);

    info!("reading params from disk");
    let mut params = phase2::MPCParameters::read(&mut params_reader, true).unwrap();

    let seed = prompt_for_randomness();
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    let contribution = params.contribute(&mut rng);
    info!("contributed: {}", hex::encode(&contribution[..]));

    info!("verifying contribution");
    let all_contributions = params
        .verify(get_porep_circuit(sector_size))
        .expect("params read from file are not valid for PoRep circuit");
    assert!(
        phase21::contains_contribution(&all_contributions, &contribution),
        "Invalid contribution"
    );

    info!("contribution success");
}

fn contribute_post(sector_size: u64, params_path: &str) {
    info!("Creating contribution for PoSt");
    let params = File::create(params_path).unwrap();
    let mut params_reader = BufReader::with_capacity(1024 * 1024, params);

    info!("reading params from disk");
    let mut params = phase2::MPCParameters::read(&mut params_reader, true).unwrap();

    let seed = prompt_for_randomness();
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    let contribution = params.contribute(&mut rng);
    info!("contributed: {}", hex::encode(&contribution[..]));

    info!("verifying contribution");
    let all_contributions = params
        .verify(get_post_circuit(sector_size))
        .expect("params read from file are not valid for PoSt circuit");
    assert!(
        phase21::contains_contribution(&all_contributions, &contribution),
        "Invalid contribution"
    );

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
    let n_params = param_paths.len();
    let n_contributions = contribution_hashes.len();

    assert!(
        n_params >= 2 && n_contributions >= 1,
        "must supply at least one pair of parameters and a single contribution hash"
    );

    assert_eq!(
        n_params,
        n_contributions - 1,
        "the number of contributions must be one less than the number of parameter files"
    );

    let mut contribution_hashes = contribution_hashes.iter();

    for (contribution_index, param_pair) in param_paths.windows(2).enumerate() {
        info!("verifying contribution {}", contribution_index);

        let params_before = {
            info!("reading 'before contribution' params from disk");
            let path = param_pair[0];
            let file = File::create(path).unwrap();
            let mut reader = BufReader::with_capacity(1024 * 1024, file);
            phase2::MPCParameters::read(&mut reader, true).unwrap()
        };

        let params_after = {
            info!("reading 'after contribution' params from disk");
            let path = param_pair[1];
            let file = File::create(path).unwrap();
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
                .help("Path to parameters file"),
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
                .help("Path to parameters file"),
        );

    let verify_command = SubCommand::with_name("verify")
        .about("Verify that a set of contributions match the provided parameters")
        .arg(
            Arg::with_name("parameters")
                .long("parameters")
                .required(true)
                .takes_value(true)
                .value_delimiter(",")
                // .min_values(2)
                .help("Comma separated list (no whitespace between items) of paths to parameters files"),
        )
        .arg(
            Arg::with_name("contributions")
                .long("contributions")
                .required(true)
                .takes_value(true)
                .case_insensitive(true)
                .value_delimiter(",")
                // .min_values(1)
                .help("An ordered (from first to last) comma separated list (no whitespace between items) of hex-encoded
                      contribution hashes - there should be no whitespace in any of the hex strings,
                      each digest must be 128 characters long, digest strings can use upper or lower
                      case hex characters"),
        );

    let app = App::new("phase2")
        .version("0.1")
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(new_command)
        .subcommand(contribute_command)
        .subcommand(verify_command);

    let matches = app.get_matches();

    match matches.subcommand() {
        (command, Some(mm)) => {
            let params_path = value_t!(mm, "parameters", String)
                .expect("Could not convert `parameters` CLI argument to string");

            let sector_size: u64 = mm
                .value_of("sector-size")
                .map(|s| match s.to_lowercase().as_ref() {
                    "1kib" => SECTOR_SIZE_ONE_KIB,
                    "16mib" => SECTOR_SIZE_16_MIB,
                    "256mib" => SECTOR_SIZE_256_MIB,
                    "1gib" => SECTOR_SIZE_1_GIB,
                    "32gib" => SECTOR_SIZE_32_GIB,
                    _ => unreachable!("Invalid CLI `sector-size` argument"),
                })
                .unwrap();

            let porep = mm.is_present("porep");
            let post = mm.is_present("post");

            match command {
                "new" => {
                    assert!(
                        porep ^ post,
                        "must supply one and only one CLI flag `--porep` or `--post`"
                    );

                    if porep {
                        initial_setup_porep(sector_size, &params_path);
                    } else {
                        initial_setup_post(sector_size, &params_path);
                    }
                }
                "contribute" => {
                    assert!(
                        porep ^ post,
                        "must supply one and only one CLI flag `--porep` or `--post`"
                    );

                    if porep {
                        contribute_porep(sector_size, &params_path);
                    } else {
                        contribute_post(sector_size, &params_path);
                    }
                }
                "verify" => {
                    let param_paths: Vec<&str> = mm.values_of("parameters").unwrap().collect();

                    let contribution_hashes: Vec<[u8; 64]> = mm
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
                _ => (),
            }
        }
        (_, None) => (),
    }
}
