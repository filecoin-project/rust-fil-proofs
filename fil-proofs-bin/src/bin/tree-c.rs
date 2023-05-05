use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::Hasher;
use filecoin_proofs::{generate_tree_c, with_shape};
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::merkle::MerkleTreeTrait;

#[derive(Debug, Deserialize, Serialize)]
struct TreeCParameters {
    input_dir: String,
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

// Wrap it in a function with `Tree` as single generic, so that it can be called via the
// `with_shape!()` macro.
fn wrapped_generate_tree_c<TreeR: 'static + MerkleTreeTrait>(
    sector_size: u64,
    input_dir: String,
    output_dir: String,
    num_layers: usize,
) -> Result<<TreeR::Hasher as Hasher>::Domain> {
    generate_tree_c::<_, _, TreeR>(sector_size, &input_dir, &output_dir, num_layers)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: TreeCParameters = cli::parse_stdin()?;
    info!("{:?}", params);
    let tree_c_root = with_shape!(
        params.sector_size,
        wrapped_generate_tree_c,
        params.sector_size,
        params.input_dir,
        params.output_dir,
        params.num_layers,
    )?;

    let output = TreeCOutput {
        comm_c: tree_c_root.into(),
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
