use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::sha256::Sha256Hasher;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_porep::stacked;

#[derive(Debug, Deserialize, Serialize)]
struct ReplicaIdParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    // Aka porep_seed.
    #[serde(with = "SerHex::<StrictPfx>")]
    porep_id: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    prover_id: [u8; 32],
    sector_id: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    ticket: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
struct ReplicaIdOutput {
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: ReplicaIdParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let replica_id = stacked::generate_replica_id::<Sha256Hasher, _>(
        &params.prover_id,
        params.sector_id,
        &params.ticket,
        &params.comm_d,
        &params.porep_id,
    )
    .into();

    let output = ReplicaIdOutput { replica_id };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
