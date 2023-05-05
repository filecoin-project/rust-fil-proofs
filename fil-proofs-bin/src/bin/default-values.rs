use std::{cmp, path::PathBuf};

use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_proofs::{constants, with_shape, PoRepConfig, PoRepProofPartitions};
use log::info;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{api_version::ApiVersion, merkle::MerkleTreeTrait, util::NODE_SIZE};
use storage_proofs_porep::stacked::DEFAULT_SYNTH_CHALLENGE_COUNT;

#[derive(Debug, Deserialize, Serialize)]
struct DefaultValuesParameters {
    sector_size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct DefaultValuesOutput {
    num_layers: usize,
    num_interactive_porep_challenges_per_partition: usize,
    num_interactive_porep_partitions: u8,
    num_synth_porep_challenges: usize,
    num_window_post_sectors: usize,
    parameters_path: String,
}

/// Division of x by y, rounding up.
/// x and y must be > 0
const fn div_ceil(x: usize, y: usize) -> usize {
    1 + ((x - 1) / y)
}

fn get_cache_params_path<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    num_porep_partitions: u8,
) -> Result<PathBuf> {
    // Getting the parameter cache filename is far from trivial. Easiest is to use the existing
    // APIs that then runs all the machinery to get tha identifier.
    let porep_config = PoRepConfig {
        sector_size: sector_size.into(),
        partitions: PoRepProofPartitions(num_porep_partitions),
        // The PoRep ID doesn't matter for getting the parameters filenames, hence we can use an
        // arbitrary value.
        porep_id: [1u8; 32],
        api_version: ApiVersion::V1_2_0,
        api_features: Vec::new(),
    };
    porep_config.get_cache_params_path::<Tree>()
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: DefaultValuesParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let num_layers = constants::get_layers(params.sector_size);
    let num_interactive_porep_partitions =
        constants::get_porep_interactive_partitions(params.sector_size);
    let num_interactive_porep_minimum_challenges =
        constants::get_porep_interactive_minimum_challenges(params.sector_size);
    let num_interactive_porep_challenges_per_partition = div_ceil(
        num_interactive_porep_minimum_challenges,
        num_interactive_porep_partitions.into(),
    );
    let num_window_post_sectors = constants::get_window_post_sector_count(params.sector_size);
    let sector_nodes = params.sector_size as usize / NODE_SIZE;
    let num_synth_porep_challenges = cmp::min(sector_nodes, DEFAULT_SYNTH_CHALLENGE_COUNT);

    let parameters_path = with_shape!(
        params.sector_size,
        get_cache_params_path,
        params.sector_size,
        num_interactive_porep_partitions,
    )?;

    let output = DefaultValuesOutput {
        num_layers,
        num_interactive_porep_challenges_per_partition,
        num_interactive_porep_partitions,
        num_window_post_sectors,
        num_synth_porep_challenges,
        parameters_path: parameters_path.to_string_lossy().to_string(),
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
