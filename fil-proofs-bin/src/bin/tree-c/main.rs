use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use filecoin_hashers::Hasher;
use filecoin_proofs::{
    get_base_tree_leafs, get_base_tree_size, with_shape, DefaultBinaryTree, DefaultPieceHasher,
};
use generic_array::typenum::{Unsigned, U11, U2};
use log::info;
use merkletree::{merkle::get_merkle_tree_len, store::StoreConfig};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    cache_key::CacheKey,
    merkle::{get_base_tree_count, split_config, MerkleTreeTrait},
    util::{default_rows_to_discard, NODE_SIZE},
};
use storage_proofs_porep::stacked::{Labels, LabelsCache, StackedDrg, BINARY_ARITY};

#[derive(Debug, Deserialize, Serialize)]
struct TreeCParameters {
    num_layers: usize,
    /// The directory where the temporary files are stored and the new files are written in.
    output_dir: String,
    sector_size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct TreeCOutput {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_c: [u8; 32],
}

/// Parses a single line and returns the parsed parameters.
fn parse_line<R: BufRead>(input: R) -> Result<TreeCParameters, serde_json::Error> {
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

// Wrap it in a function with `Tree` as single generic, so that it can be called via the
// `with_shape!()` macro.
fn generate_tree_c<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    cache_path: String,
    num_layers: usize,
) -> Result<<Tree::Hasher as Hasher>::Domain> {
    // TODO vmx 2023-04-05: double check if `nodes_count` calculation is correct.
    let leaf_count = sector_size as usize / NODE_SIZE;
    let tree_count = get_base_tree_count::<Tree>();
    let nodes_count = leaf_count / tree_count;

    let rows_to_discard = default_rows_to_discard(nodes_count, Tree::Arity::to_usize());
    let size = Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?);
    let tree_c_config = StoreConfig {
        path: PathBuf::from(&cache_path),
        id: CacheKey::CommCTree.to_string(),
        size,
        rows_to_discard,
    };
    let configs = split_config(tree_c_config.clone(), tree_count)?;

    let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(sector_size.into())?;
    let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;
    let label_configs = (1..=num_layers)
        .map(|layer| StoreConfig {
            path: PathBuf::from(&cache_path),
            id: CacheKey::label_layer(layer),
            size: Some(base_tree_leafs),
            rows_to_discard: default_rows_to_discard(base_tree_leafs, BINARY_ARITY),
        })
        .collect();
    let labels = Labels::new(label_configs);
    let labels_cache =
        LabelsCache::<Tree>::new(&labels).context("failed to create labels cache")?;

    let tree_c = match num_layers {
        2 => StackedDrg::<Tree, DefaultPieceHasher>::generate_tree_c::<U2, Tree::Arity>(
            nodes_count,
            tree_count,
            configs,
            &labels_cache,
        )?,
        11 => StackedDrg::<Tree, DefaultPieceHasher>::generate_tree_c::<U11, Tree::Arity>(
            nodes_count,
            tree_count,
            configs,
            &labels_cache,
        )?,
        _ => return Err(anyhow!("Unsupported column arity")),
    };

    Ok(tree_c.root())
}

pub fn color_logger_format(
    writer: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &flexi_logger::Record,
) -> Result<(), std::io::Error> {
    const DEFAULT_TIME_FORMAT: &str = "%Y-%m-%dT%H:%M:%S%.3f";
    let level = record.level();
    write!(
        writer,
        "{} [{}] {} {} > {}",
        now.now().format(DEFAULT_TIME_FORMAT),
        flexi_logger::style(level).paint(std::thread::current().name().unwrap_or("<unnamed>")),
        flexi_logger::style(level).paint(level.to_string()),
        record.module_path().unwrap_or("<unnamed>"),
        record.args(),
    )
}


fn main() -> Result<()> {
    let _ = flexi_logger::Logger::try_with_env()
        .expect("Invalid RUST_LOG")
        .format(color_logger_format)
        .start();


    let params = parse_line(BufReader::new(io::stdin()))?;
    info!("{:?}", params);

    let tree_c_root = with_shape!(
        params.sector_size,
        generate_tree_c,
        params.sector_size,
        params.output_dir,
        params.num_layers,
    )?;

    let output = TreeCOutput {
        comm_c: tree_c_root.into(),
    };
    info!("{:?}", output);
    print_line(&mut BufWriter::new(io::stdout()), output)?;

    Ok(())
}
