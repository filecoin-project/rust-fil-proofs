use std::fmt;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use anyhow::Result;
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
    LayerChallenges, SetupParams, StackedDrg, BINARY_ARITY, EXP_DEGREE,
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

// TODO vmx 2023-03-29: The output layers filenames might not be needed as those are hard-coded
// names only depending on the number of layers.
#[derive(Debug, Deserialize, Serialize)]
struct SdrOutput {
    layers: Vec<PathBuf>,
}

/// Parses a single line and returns the parsed parameters.
fn parse_line<R: BufRead>(input: R) -> Result<SdrParameters, serde_json::Error> {
    let line = input
        .lines()
        .next()
        .expect("Nothing to iterate")
        .expect("Failed to read line");
    serde_json::from_str(&line)
}

/// Outputs an object serialized as JSON.
fn print_line<W: Write, S: Serialize>(output: &mut W, data: S) -> Result<()> {
    let line = serde_json::to_vec(&data)?;
    output.write_all(&line)?;
    output.write_all(&[b'\n'])?;
    Ok(())
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params = parse_line(BufReader::new(io::stdin()))?;
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
        layer_challenges: LayerChallenges::new(params.num_layers, 0),
        api_version: ApiVersion::V1_2_0,
    };
    let public_params = SdrStackedDrg::setup(&setup_params)?;

    let (_labels, layer_states) =
        SdrStackedDrg::replicate_phase1(&public_params, &params.replica_id.into(), config.clone())?;
    let layers = layer_states
        .iter()
        .map(|state| StoreConfig::data_path(&state.config.path, &state.config.id))
        .collect::<Vec<_>>();
    let output = SdrOutput { layers };
    info!("{:?}", output);
    print_line(&mut BufWriter::new(io::stdout()), output)?;

    Ok(())
}
