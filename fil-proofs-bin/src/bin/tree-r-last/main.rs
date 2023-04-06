use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use filecoin_hashers::Hasher;
use filecoin_proofs::{
    get_base_tree_leafs, get_base_tree_size, with_shape, DefaultBinaryTree, DefaultPieceHasher,
};
use generic_array::typenum::Unsigned;
use log::info;
use memmap2::MmapOptions;
use merkletree::{
    merkle::get_merkle_tree_len,
    store::{DiskStore, Store, StoreConfig},
};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    cache_key::CacheKey,
    data::Data,
    merkle::{get_base_tree_count, MerkleTreeTrait},
    util::{default_rows_to_discard, NODE_SIZE},
};
use storage_proofs_porep::stacked::StackedDrg;

#[derive(Debug, Deserialize, Serialize)]
struct TreeRLastParameters {
    num_layers: usize,
    /// The directory where the temporary files are stored and the new files are written in.
    output_dir: String,
    /// This is a path to a copy of the original sector data that will be manipulated in-place.
    replica_path: String,
    sector_size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct TreeRLastOutput {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r_last: [u8; 32],
}

/// Parses a single line and returns the parsed parameters.
fn parse_line<R: BufRead>(input: R) -> Result<TreeRLastParameters, serde_json::Error> {
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
fn generate_tree_r_last<Tree: 'static + MerkleTreeTrait>(
    data: &mut Data<'_>,
    sector_size: u64,
    cache_path: String,
    replica_path: String,
    //label_configs: Vec<StoreConfig>,
    //labels_config: StoreConfig,
    num_layers: usize,
    //) -> Result<<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain> {
) -> Result<<Tree::Hasher as Hasher>::Domain> {
    // TODO vmx 2023-04-05: double check if `nodes_count` calculation is correct.
    let leaf_count = sector_size as usize / NODE_SIZE;
    let tree_count = get_base_tree_count::<Tree>();
    let nodes_count = leaf_count / tree_count;

    let rows_to_discard = default_rows_to_discard(nodes_count, Tree::Arity::to_usize());
    let size = Some(get_merkle_tree_len(nodes_count, Tree::Arity::to_usize())?);
    let tree_r_last_config = StoreConfig {
        path: PathBuf::from(&cache_path),
        id: CacheKey::CommRLastTree.to_string(),
        size,
        // A default 'rows_to_discard' value will be chosen for tree_r_last, unless the user
        // overrides this value via the environment setting (FIL_PROOFS_ROWS_TO_DISCARD). If
        // this value is specified, no checking is done on it and it may result in a broken
        // configuration. *Use with caution*. It must be noted that if/when this unchecked
        // value is passed through merkle_light, merkle_light now does a check that does not
        // allow us to discard more rows than is possible to discard.
        rows_to_discard,
    };

    let base_tree_size = get_base_tree_size::<DefaultBinaryTree>(sector_size.into())?;
    let base_tree_leafs = get_base_tree_leafs::<DefaultBinaryTree>(base_tree_size)?;
    // TODO vmx 2023-04-05: Currently there's no way to specify a path directly, we rely on
    // `merkletree`s internal storage abstraction. Hence we need to speciy the `id` in the
    // `StoreConfig` correctly.
    let last_layer_labels = DiskStore::new_from_disk(
        base_tree_leafs,
        Tree::Arity::to_usize(),
        // For the discore only the directory `path` and the `id` matters, the rest can have
        // arbitrary values.
        &StoreConfig {
            path: PathBuf::from(&cache_path),
            id: CacheKey::label_layer(num_layers),
            size: None,
            rows_to_discard: 0,
        },
    )?;

    let tree_r_last = StackedDrg::<Tree, DefaultPieceHasher>::generate_tree_r_last(
        data,
        nodes_count,
        tree_count,
        tree_r_last_config,
        PathBuf::from(replica_path),
        &last_layer_labels,
        // TODO vmx 2023-04-06: If we pass in an no-op function, then I think the replica is not
        // touched.
        None,
    )?;
    Ok(tree_r_last.root())
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params = parse_line(BufReader::new(io::stdin()))?;
    info!("{:?}", params);

    let f_data = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&params.replica_path)
        .with_context(|| format!("could not open replica_path={}", params.replica_path))?;
    let data = unsafe {
        MmapOptions::new()
            .map_mut(&f_data)
            .with_context(|| format!("could not mmap replica_path={}", params.replica_path))?
    };
    let mut data: Data<'_> = (data, PathBuf::from(&params.replica_path)).into();

    let tree_r_last_root = with_shape!(
        params.sector_size,
        generate_tree_r_last,
        &mut data,
        params.sector_size,
        params.output_dir,
        params.replica_path,
        params.num_layers,
    )?;

    let output = TreeRLastOutput {
        comm_r_last: tree_r_last_root.into(),
    };
    info!("{:?}", output);
    print_line(&mut BufWriter::new(io::stdout()), output)?;

    Ok(())
}
