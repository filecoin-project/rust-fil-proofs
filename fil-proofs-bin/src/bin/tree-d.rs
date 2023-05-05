use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use blstrs::Scalar as Fr;
use fil_proofs_bin::cli;
use filecoin_proofs::{
    commitment_from_fr, get_base_tree_leafs, get_base_tree_size, DefaultBinaryTree,
    DefaultPieceHasher,
};
use log::{info, trace};
use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    cache_key::CacheKey,
    merkle::{create_base_merkle_tree, BinaryMerkleTree},
    util::default_rows_to_discard,
};
use storage_proofs_porep::stacked::BINARY_ARITY;

#[derive(Debug, Deserialize, Serialize)]
struct TreeDParameters {
    /// Path to the already Fr32 padded input file.
    input_path: String,
    /// The directory where the temporary files are stored and the new files are written in.
    output_dir: String,
    sector_size: u64,
}

#[derive(Deserialize, Serialize)]
struct TreeDOutput {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
}

impl fmt::Debug for TreeDOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommdOutput")
            .field("comm_d", &format!("0x{}", hex::encode(self.comm_d)))
            .finish()
    }
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: TreeDParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    trace!("building merkle tree for the original data");
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

    let mut data_file = File::open(&params.input_path)
        .with_context(|| format!("could not open input_path={}", params.input_path))?;
    let mut data = Vec::with_capacity(
        usize::try_from(params.sector_size)
            .expect("sector size must fit into the platform's bit size"),
    );
    data_file.read_to_end(&mut data)?;

    let data_tree = create_base_merkle_tree::<BinaryMerkleTree<DefaultPieceHasher>>(
        Some(config),
        base_tree_leafs,
        &data,
    )?;

    let comm_d_root: Fr = data_tree.root().into();
    let comm_d = commitment_from_fr(comm_d_root);

    let output = TreeDOutput { comm_d };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
