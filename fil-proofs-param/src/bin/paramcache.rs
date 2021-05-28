use std::env;
use std::process::exit;
use std::str::FromStr;

use dialoguer::{theme::ColorfulTheme, MultiSelect};
use filecoin_proofs::{
    constants::{
        DefaultPieceHasher, POREP_PARTITIONS, PUBLISHED_SECTOR_SIZES, WINDOW_POST_CHALLENGE_COUNT,
        WINDOW_POST_SECTOR_COUNT, WINNING_POST_CHALLENGE_COUNT, WINNING_POST_SECTOR_COUNT,
    },
    parameters::{public_params, window_post_public_params, winning_post_public_params},
    types::{PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, SectorSize},
    with_shape, PoStType,
};
use humansize::{file_size_opts, FileSize};
use indicatif::ProgressBar;
use log::{error, info, warn};
use rand::rngs::OsRng;
use storage_proofs_core::{
    api_version::ApiVersion, compound_proof::CompoundProof, merkle::MerkleTreeTrait,
    parameter_cache::CacheableParameters,
};
use storage_proofs_porep::stacked::{StackedCircuit, StackedCompound, StackedDrg};
use storage_proofs_post::fallback::{FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound};
use structopt::StructOpt;

fn cache_porep_params<Tree: 'static + MerkleTreeTrait>(porep_config: PoRepConfig) {
    info!("generating PoRep groth params");

    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )
    .expect("failed to get public params from config");

    let circuit = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<Tree, DefaultPieceHasher>,
        StackedCircuit<Tree, DefaultPieceHasher>,
    >>::blank_circuit(&public_params);

    let _ = StackedCompound::<Tree, DefaultPieceHasher>::get_param_metadata(
        circuit.clone(),
        &public_params,
    )
    .expect("failed to get metadata");

    let _ = StackedCompound::<Tree, DefaultPieceHasher>::get_groth_params(
        Some(&mut OsRng),
        circuit.clone(),
        &public_params,
    )
    .expect("failed to get groth params");

    let _ = StackedCompound::<Tree, DefaultPieceHasher>::get_verifying_key(
        Some(&mut OsRng),
        circuit,
        &public_params,
    )
    .expect("failed to get verifying key");
}

fn cache_winning_post_params<Tree: 'static + MerkleTreeTrait>(post_config: &PoStConfig) {
    info!("generating Winning-PoSt groth params");

    let public_params = winning_post_public_params::<Tree>(post_config)
        .expect("failed to get public params from config");

    let circuit = <FallbackPoStCompound<Tree> as CompoundProof<
        FallbackPoSt<Tree>,
        FallbackPoStCircuit<Tree>,
    >>::blank_circuit(&public_params);

    let _ = <FallbackPoStCompound<Tree>>::get_param_metadata(circuit.clone(), &public_params)
        .expect("failed to get metadata");

    let _ = <FallbackPoStCompound<Tree>>::get_groth_params(
        Some(&mut OsRng),
        circuit.clone(),
        &public_params,
    )
    .expect("failed to get groth params");

    let _ =
        <FallbackPoStCompound<Tree>>::get_verifying_key(Some(&mut OsRng), circuit, &public_params)
            .expect("failed to get verifying key");
}

fn cache_window_post_params<Tree: 'static + MerkleTreeTrait>(post_config: &PoStConfig) {
    info!("generating Window-PoSt groth params");

    let public_params = window_post_public_params::<Tree>(post_config)
        .expect("failed to get public params from config");

    let circuit: FallbackPoStCircuit<Tree> = <FallbackPoStCompound<Tree> as CompoundProof<
        FallbackPoSt<Tree>,
        FallbackPoStCircuit<Tree>,
    >>::blank_circuit(&public_params);

    let _ = <FallbackPoStCompound<Tree>>::get_param_metadata(circuit.clone(), &public_params)
        .expect("failed to get metadata");

    let _ = <FallbackPoStCompound<Tree>>::get_groth_params(
        Some(&mut OsRng),
        circuit.clone(),
        &public_params,
    )
    .expect("failed to get groth params");

    let _ =
        <FallbackPoStCompound<Tree>>::get_verifying_key(Some(&mut OsRng), circuit, &public_params)
            .expect("failed to get verifying key");
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "paramcache",
    about = "generates and caches SDR PoRep, Winning-PoSt, and Window-PoSt groth params"
)]
struct Opt {
    #[structopt(long, help = "Only cache PoSt groth params.")]
    only_post: bool,
    #[structopt(
        short = "z",
        long,
        use_delimiter = true,
        help = "A comma-separated list of sector sizes (in number of bytes)."
    )]
    sector_sizes: Vec<u64>,
    #[structopt(
        long = "api-version",
        value_name = "SEMANTIC VERSION",
        default_value = "1.1.0",
        help = "Use a specific rust-fil-proofs API version."
    )]
    api_version: String,
}

fn generate_params_post(sector_size: u64, api_version: ApiVersion) {
    with_shape!(
        sector_size,
        cache_winning_post_params,
        &PoStConfig {
            sector_size: SectorSize(sector_size),
            challenge_count: WINNING_POST_CHALLENGE_COUNT,
            sector_count: WINNING_POST_SECTOR_COUNT,
            typ: PoStType::Winning,
            priority: true,
            api_version,
        }
    );

    with_shape!(
        sector_size,
        cache_window_post_params,
        &PoStConfig {
            sector_size: SectorSize(sector_size),
            challenge_count: WINDOW_POST_CHALLENGE_COUNT,
            sector_count: *WINDOW_POST_SECTOR_COUNT
                .read()
                .expect("WINDOW_POST_SECTOR_COUNT poisoned")
                .get(&sector_size)
                .expect("unknown sector size"),
            typ: PoStType::Window,
            priority: true,
            api_version,
        }
    );
}

fn generate_params_porep(sector_size: u64, api_version: ApiVersion) {
    with_shape!(
        sector_size,
        cache_porep_params,
        PoRepConfig {
            sector_size: SectorSize(sector_size),
            partitions: PoRepProofPartitions(
                *POREP_PARTITIONS
                    .read()
                    .expect("POREP_PARTITIONS poisoned")
                    .get(&sector_size)
                    .expect("unknown sector size"),
            ),
            porep_id: [0; 32],
            api_version,
        }
    );
}

pub fn main() {
    // Create a stderr logger for all log levels.
    env::set_var("RUST_LOG", "paramcache");
    fil_logger::init();

    let mut opts = Opt::from_args();

    // If no sector-sizes were given provided via. the CLI, display an interactive menu. Otherwise,
    // filter out invalid CLI sector-size arguments.
    if opts.sector_sizes.is_empty() {
        let sector_size_strings: Vec<String> = PUBLISHED_SECTOR_SIZES
            .iter()
            .map(|sector_size| {
                let human_size = sector_size
                    .file_size(file_size_opts::BINARY)
                    .expect("failed to format sector size");
                // Right align numbers for easier reading.
                format!("{: >7}", human_size)
            })
            .collect();

        opts.sector_sizes = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt(
                "Select the sizes that should be generated if not already cached [use space key to \
                select, press return to finish]",
            )
            .items(&sector_size_strings)
            .interact()
            .expect("interaction failed")
            .into_iter()
            .map(|i| PUBLISHED_SECTOR_SIZES[i])
            .collect();
    } else {
        opts.sector_sizes.retain(|size| {
            if PUBLISHED_SECTOR_SIZES.contains(size) {
                true
            } else {
                let human_size = size
                    .file_size(file_size_opts::BINARY)
                    .expect("failed to humansize sector size argument");
                warn!("ignoring invalid sector size argument: {}", human_size);
                false
            }
        });
    }

    if opts.sector_sizes.is_empty() {
        error!("no valid sector sizes given, aborting");
        exit(1);
    }

    let api_version = ApiVersion::from_str(&opts.api_version)
        .expect("Cannot parse API version from semver string (e.g. 1.1.0)");

    for sector_size in opts.sector_sizes {
        let human_size = sector_size
            .file_size(file_size_opts::BINARY)
            .expect("failed to format sector size");
        let message = format!("Generating sector size: {}", human_size);
        info!("{}", &message);

        let spinner = ProgressBar::new_spinner();
        spinner.set_message(&message);
        spinner.enable_steady_tick(100);

        generate_params_post(sector_size, api_version);

        if !opts.only_post {
            generate_params_porep(sector_size, api_version);
        }

        spinner.finish_with_message(&format!("✔ {}", &message));
    }
}
