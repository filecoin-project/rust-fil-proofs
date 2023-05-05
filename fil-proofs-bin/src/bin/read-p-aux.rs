use std::fs;

use anyhow::{Context, Result};
use bincode::deserialize;
use fil_proofs_bin::cli;
use filecoin_proofs::DefaultTreeDomain;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_porep::stacked::PersistentAux;

#[derive(Debug, Deserialize, Serialize)]
struct ReadPAuxParameters {
    p_aux_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReadPAuxOutput {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_c: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r_last: [u8; 32],
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: ReadPAuxParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let p_aux_bytes = fs::read(&params.p_aux_path)
        .with_context(|| format!("could not read file p_aux={:?}", params.p_aux_path))?;
    // It's just the `CommC` and `CommRLast` bytes concatenated. We use the bincode deserializer
    // just to be safe.
    let p_aux: PersistentAux<DefaultTreeDomain> = deserialize(&p_aux_bytes)?;

    let output = ReadPAuxOutput {
        comm_c: p_aux.comm_c.into(),
        comm_r_last: p_aux.comm_r_last.into(),
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
