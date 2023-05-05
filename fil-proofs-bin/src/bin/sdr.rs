use std::{fmt, path::PathBuf};

use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_proofs::{
    get_base_tree_leafs, get_base_tree_size, DefaultBinaryTree, DefaultPieceHasher,
};
use log::{info, trace};
use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    api_version::ApiVersion, cache_key::CacheKey, drgraph::BASE_DEGREE, proof::ProofScheme,
    util::default_rows_to_discard,
};
use storage_proofs_porep::stacked::{
    Challenges, SetupParams, StackedDrg, BINARY_ARITY, EXP_DEGREE,
};

/// For SDR we use the `DefaultBinaryTree` as the tree to built upon. This is technically not
/// correct. The current sealing code expects using the same tree shape (which depends on the
/// secotr size) for all phases. But as we have independent binaries, it doesn't matter as we don't
/// share Rust types accross the binary boundary.
type SdrStackedDrg<'a> = StackedDrg<'a, DefaultBinaryTree, DefaultPieceHasher>;

#[derive(Deserialize, Serialize)]
struct SdrParameters {
    num_layers: usize,
    output_dir: String,
    #[serde(with = "SerHex::<StrictPfx>")]
    porep_id: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
    sector_size: u64,
}

impl fmt::Debug for SdrParameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SdrParameters")
            .field("num_layers", &self.num_layers)
            .field("output_dir", &self.output_dir)
            .field("porep_id", &format!("0x{}", hex::encode(self.porep_id)))
            .field("replica_id", &format!("0x{}", hex::encode(self.replica_id)))
            .field("sector_size", &self.sector_size)
            .finish()
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct SdrOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: SdrParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(params.sector_size.into())?;
    let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;
    trace!(
        "sector_size {}, base tree size {}, base tree leafs {}",
        params.sector_size,
        base_tree_size,
        base_tree_leafs,
    );
    let config = StoreConfig::new(
        PathBuf::from(params.output_dir),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
    );
    let setup_params = SetupParams {
        nodes: base_tree_leafs,
        degree: BASE_DEGREE,
        expansion_degree: EXP_DEGREE,
        porep_id: params.porep_id,
        // For SDR the number of challenges doesn't matter, hence we can set it to 0.
        challenges: Challenges::new_interactive(0),
        num_layers: params.num_layers,
        api_version: ApiVersion::V1_2_0,
        api_features: Vec::new(),
    };
    let public_params = SdrStackedDrg::setup(&setup_params)?;

    SdrStackedDrg::replicate_phase1(&public_params, &params.replica_id.into(), config.path)?;
    let output = SdrOutput::default();
    cli::print_stdout(output)?;

    Ok(())
}
