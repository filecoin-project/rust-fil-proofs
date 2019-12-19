use phase21 as phase2;
use std::fs::File;
use std::io::{BufReader, BufWriter};

use clap::{value_t, App, AppSettings, Arg, SubCommand};
use filecoin_proofs::constants::{
    DefaultPieceHasher, DefaultTreeHasher, DEFAULT_POREP_PROOF_PARTITIONS, SECTOR_SIZE_ONE_KIB,
};
use filecoin_proofs::parameters::setup_params;
use filecoin_proofs::types::*;
use log::info;
use rand::SeedableRng;
use storage_proofs::circuit::stacked::StackedCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::stacked::StackedDrg;

fn initial_setup(params_path: &str) {
    let params = File::create(params_path).unwrap();
    let mut params = BufWriter::with_capacity(1024 * 1024, params);

    // Generate params for PoRep
    {
        info!("Creating params for PoRep");

        // TODO: allow for different sizes
        let porep_config = PoRepConfig {
            sector_size: SectorSize(SECTOR_SIZE_ONE_KIB),
            partitions: DEFAULT_POREP_PROOF_PARTITIONS,
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
        let stacked_blank_circuit = <StackedCompound as CompoundProof<
            _,
            StackedDrg<DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::blank_circuit(&public_params.vanilla_params);

        phase2::MPCParameters::new(stacked_blank_circuit)
            .unwrap()
            .write(&mut params)
            .unwrap();
    }

    // TODO: Generate params for PoSt
}

fn contribute(params_path: &str) {
    let params = File::create(params_path).unwrap();
    let mut params_reader = BufReader::with_capacity(1024 * 1024, params);

    info!("reading params from disk");
    let mut params = phase2::MPCParameters::read(&mut params_reader, true).unwrap();

    let seed = prompt_for_randomness();
    let mut rng = rand_chacha::ChaChaRng::from_seed(seed);

    let contribution = params.contribute(&mut rng);
    info!("contributed: {}", hex::encode(&contribution[..]));

    // TODO: add verification check
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

fn verify(params_path: &str) {
    // TODO: add method for verification
}

fn main() {
    simplelog::SimpleLogger::init(log::LevelFilter::Info, simplelog::Config::default())
        .expect("failed to init logger");

    let new_command = SubCommand::with_name("new").about("Create parameters").arg(
        Arg::with_name("parameters")
            .long("parameters")
            .help("Path to parameters file"),
    );

    let contribute_command = SubCommand::with_name("contribute")
        .about("Contribute to parameters")
        .arg(
            Arg::with_name("parameters")
                .long("parameters")
                .help("Path to parameters file"),
        );

    let verify_command = SubCommand::with_name("verify")
        .about("Verify parameters")
        .arg(
            Arg::with_name("parameters")
                .long("parameters")
                .help("Path to parameters file"),
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

            match command {
                "new" => {
                    initial_setup(&params_path);
                }
                "contribute" => {
                    contribute(&params_path);
                }
                "verify" => {
                    verify(&params_path);
                }
                _ => (),
            }
        }
        (_, None) => (),
    }
}
