use std::fmt;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use anyhow::Result;
use filecoin_proofs::{
    get_base_tree_leafs, get_base_tree_size, seal_pre_commit_phase2, DefaultBinaryTree,
    PoRepConfig, SealPreCommitOutput, SealPreCommitPhase1Output,
};
use log::info;
use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    api_version::ApiVersion, cache_key::CacheKey, util::default_rows_to_discard,
};
use storage_proofs_porep::stacked::{Labels, BINARY_ARITY};

// For PC2 the PoRep ID is not used anywhere, hence we can use an arbitray one.
const ARBITRARY_POREP_ID: [u8; 32] = [0; 32];

#[derive(Deserialize, Serialize)]
struct Pc2Parameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    num_layers: usize,
    /// The directory where the temporary files are stored and the new files are written in.
    output_dir: String,
    partitions: usize,
    /// This is a path to a copy of the original sector data that will be manipulated in-place.
    replica_path: String,
    sector_size: u64,
}

impl fmt::Debug for Pc2Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pc2Parameters")
            .field("comm_d", &format!("0x{}", hex::encode(self.comm_d)))
            .field("num_layers", &self.num_layers)
            .field("output_dir", &self.output_dir)
            .field("partitions", &self.partitions)
            .field("replica_path", &self.replica_path)
            .field("sector_size", &self.sector_size)
            .finish()
    }
}

// TODO vmx 2023-03-29: should probably also return `p_aux` and `t_aux`.
#[derive(Debug, Deserialize, Serialize)]
struct Pc2Output {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
}

/// Parses a single line and returns the parsed parameters.
fn parse_line<R: BufRead>(input: R) -> Result<Pc2Parameters, serde_json::Error> {
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

    let porep_config =
        PoRepConfig::new_groth16(params.sector_size, ARBITRARY_POREP_ID, ApiVersion::V1_2_0);

    let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(params.sector_size.into())?;
    let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;
    let config = StoreConfig::new(
        PathBuf::from(params.output_dir.clone()),
        CacheKey::CommDTree.to_string(),
        default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
    );
    let labels = (1..=params.num_layers)
        .map(|layer| StoreConfig {
            path: params.output_dir.clone().into(),
            id: CacheKey::label_layer(layer),
            size: Some(base_tree_leafs),
            rows_to_discard: default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
        })
        .collect();
    let phase1_output = SealPreCommitPhase1Output::<DefaultBinaryTree> {
        labels: Labels::new(labels),
        config,
        comm_d: params.comm_d,
    };

    let SealPreCommitOutput { comm_r, .. } = seal_pre_commit_phase2(
        &porep_config,
        phase1_output,
        params.output_dir,
        params.replica_path,
    )?;

    let output = Pc2Output { comm_r };
    info!("{:?}", output);
    print_line(&mut BufWriter::new(io::stdout()), output)?;

    Ok(())
}
