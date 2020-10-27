use dialoguer::{theme::ColorfulTheme, MultiSelect};
use humansize::{file_size_opts, FileSize};
use log::{info, warn};
use structopt::StructOpt;

use bellperson::util_cs::bench_cs::BenchCS;
use bellperson::{bls::Bls12, Circuit};
use filecoin_proofs::constants::*;
use filecoin_proofs::parameters::{
    public_params, window_post_public_params, winning_post_public_params,
};
use filecoin_proofs::types::*;
use filecoin_proofs::with_shape;
use filecoin_proofs::PoStType;
use storage_proofs::compound_proof::CompoundProof;
use storage_proofs::porep::stacked::{StackedCompound, StackedDrg};
use storage_proofs::post::fallback::{FallbackPoSt, FallbackPoStCircuit, FallbackPoStCompound};

struct CircuitInfo {
    constraints: usize,
    inputs: usize,
}

fn circuit_info<C: Circuit<Bls12>>(circuit: C) -> CircuitInfo {
    let mut cs_blank = BenchCS::new();
    circuit
        .synthesize(&mut cs_blank)
        .expect("failed to synthesize");

    CircuitInfo {
        constraints: cs_blank.num_constraints(),
        inputs: cs_blank.num_inputs(),
    }
}

fn get_porep_info<Tree: 'static + MerkleTreeTrait>(porep_config: PoRepConfig) -> CircuitInfo {
    info!("PoRep info");

    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
    )
    .expect("failed to get public params from config");

    let circuit = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<Tree, DefaultPieceHasher>,
        _,
    >>::blank_circuit(&public_params);

    circuit_info(circuit)
}

fn get_winning_post_info<Tree: 'static + MerkleTreeTrait>(post_config: &PoStConfig) -> CircuitInfo {
    info!("Winning PoSt info");

    let post_public_params = winning_post_public_params::<Tree>(post_config)
        .expect("failed to get public params from config");

    let circuit: FallbackPoStCircuit<Tree> = <FallbackPoStCompound<Tree> as CompoundProof<
        FallbackPoSt<Tree>,
        FallbackPoStCircuit<Tree>,
    >>::blank_circuit(&post_public_params);

    circuit_info(circuit)
}

fn get_window_post_info<Tree: 'static + MerkleTreeTrait>(post_config: &PoStConfig) -> CircuitInfo {
    info!("Window PoSt info");

    let post_public_params = window_post_public_params::<Tree>(post_config)
        .expect("failed to get public params from config");

    let circuit: FallbackPoStCircuit<Tree> = <FallbackPoStCompound<Tree> as CompoundProof<
        FallbackPoSt<Tree>,
        FallbackPoStCircuit<Tree>,
    >>::blank_circuit(&post_public_params);

    circuit_info(circuit)
}

#[derive(Debug, StructOpt)]
#[structopt(name = "paramcache")]
struct Opt {
    #[structopt(long)]
    winning: bool,
    #[structopt(long)]
    window: bool,
    #[structopt(long)]
    porep: bool,
    #[structopt(short = "z", long, use_delimiter = true)]
    constraints_for_sector_sizes: Vec<u64>,
}

fn winning_post_info(sector_size: u64) -> CircuitInfo {
    with_shape!(
        sector_size,
        get_winning_post_info,
        &PoStConfig {
            sector_size: SectorSize(sector_size),
            challenge_count: WINNING_POST_CHALLENGE_COUNT,
            sector_count: WINNING_POST_SECTOR_COUNT,
            typ: PoStType::Winning,
            priority: true,
        }
    )
}

fn window_post_info(sector_size: u64) -> CircuitInfo {
    with_shape!(
        sector_size,
        get_window_post_info,
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
        }
    )
}

fn porep_info(sector_size: u64) -> (CircuitInfo, usize) {
    let partitions = PoRepProofPartitions(
        *POREP_PARTITIONS
            .read()
            .expect("POREP_PARTITIONS poisoned")
            .get(&sector_size)
            .expect("unknown sector size"),
    );
    let info = with_shape!(
        sector_size,
        get_porep_info,
        PoRepConfig {
            sector_size: SectorSize(sector_size),
            partitions,
            porep_id: [0; 32],
        }
    );
    (info, partitions.into())
}

// Run this from the command-line to get info about circuits.
pub fn main() {
    // The logger is used and every message from this tool is also logged into those logs.
    // Though the information is also printed to stdout, so that users who haven't set the
    // `RUST_LOG` environment variable also see warngings/progress.
    fil_logger::init();

    let opts = Opt::from_args();

    // Display interactive menu if no sizes are given
    let sizes: Vec<u64> = if opts.constraints_for_sector_sizes.is_empty() {
        let sector_sizes = PUBLISHED_SECTOR_SIZES
            .iter()
            .map(|sector_size| {
                // Right aligning the numbers makes them easier to read
                format!(
                    "{: >7}",
                    sector_size
                        .file_size(file_size_opts::BINARY)
                        .expect("failed to format sector size"),
                )
            })
            .collect::<Vec<_>>();

        let selected_sector_sizes = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Select the sizes for which constraints should be counted [use space key to select]")
            .items(&sector_sizes[..])
            .interact()
            .expect("interaction failed");

        // Extract the selected sizes
        PUBLISHED_SECTOR_SIZES
            .iter()
            .enumerate()
            .filter_map(|(index, size)| {
                if selected_sector_sizes.contains(&index) {
                    Some(*size)
                } else {
                    None
                }
            })
            .collect()
    } else {
        opts.constraints_for_sector_sizes
            .into_iter()
            .filter(|size| {
                if PUBLISHED_SECTOR_SIZES.contains(size) {
                    return true;
                }

                warn!("ignoring invalid sector size: {}", size);
                println!("ignoring invalid sector size: {}", size);
                false
            })
            .collect()
    };

    if sizes.is_empty() {
        info!("No valid sector sizes given. Abort.");
        println!("No valid sector sizes given. Abort.");
    }

    let count_winning = opts.winning;
    let count_window = opts.window;
    let count_porep = opts.porep;

    for sector_size in sizes {
        let human_size = sector_size
            .file_size(file_size_opts::BINARY)
            .expect("failed to format sector size");
        println!("Getting circuit info for sector size: {}", human_size);

        if count_winning {
            let info = winning_post_info(sector_size);
            println!(
                "{} Winning PoSt constraints: {}, public inputs: {}, partitions: 1",
                human_size, info.constraints, info.inputs
            );
        }

        if count_window {
            let info = window_post_info(sector_size);
            println!(
                "{} Window PoSt constraints (per partition): {}, public inputs (per partition): {}, partitions: <depends on input size>",
                human_size, info.constraints, info.inputs
            );
        }

        if count_porep {
            let (info, partitions) = porep_info(sector_size);
            println!(
                "{} PoRep constraints: {}, public inputs: {}, partitions: {}",
                human_size, info.constraints, info.inputs, partitions
            );
        }
    }
}
