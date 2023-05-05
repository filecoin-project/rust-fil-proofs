use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::Hasher;
use filecoin_proofs::{generate_tree_r_last, with_shape};
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::merkle::MerkleTreeTrait;
use storage_proofs_update::constants::TreeRHasher;

#[derive(Debug, Deserialize, Serialize)]
struct TreeRLastParameters {
    /// The directory where the temporary files are stored and the new files are written in.
    output_dir: String,
    /// This is the path to the encoded replica file.
    replica_path: String,
    sector_size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct TreeRLastOutput {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r_last: [u8; 32],
}

// Wrap it in a function with `Tree` as single generic, so that it can be called via the
// `with_shape!()` macro.
fn wrapped_generate_tree_r_last<TreeR: 'static + MerkleTreeTrait<Hasher = TreeRHasher>>(
    sector_size: u64,
    replica_path: String,
    output_dir: String,
) -> Result<<TreeR::Hasher as Hasher>::Domain> {
    generate_tree_r_last::<_, _, TreeR>(sector_size, &replica_path, &output_dir)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: TreeRLastParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let tree_r_last_root = with_shape!(
        params.sector_size,
        wrapped_generate_tree_r_last,
        params.sector_size,
        params.replica_path,
        params.output_dir,
    )?;

    let output = TreeRLastOutput {
        comm_r_last: tree_r_last_root.into(),
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
