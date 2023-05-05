use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::{poseidon::PoseidonFunction, HashFunction};
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};

#[derive(Debug, Deserialize, Serialize)]
struct CommRParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_c: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r_last: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
struct CommROutput {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: CommRParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    // comm_r = H(comm_c || comm_r_last)
    let comm_r = PoseidonFunction::hash2(&params.comm_c.into(), &params.comm_r_last.into());

    let output = CommROutput {
        comm_r: comm_r.into(),
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
