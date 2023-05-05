// Same as:
// cat precommit-phase2-output | xxd -p -c 32 | sed 'N;s/\(.*\)\n\(.*\)/{"comm_r": "0x\1","comm_d": "0x\2"}/

use std::fs;

use anyhow::{Context, Result};
use bincode::deserialize;
use fil_proofs_bin::cli;
use filecoin_proofs::SealPreCommitOutput;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};

#[derive(Debug, Deserialize, Serialize)]
struct ReadPreCommitPhase2OutputParameters {
    pre_commit_phase2_output_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReadPreCommitPhase2Output {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: ReadPreCommitPhase2OutputParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let pre_commit_phase2_output_bytes = fs::read(&params.pre_commit_phase2_output_path)
        .with_context(|| {
            format!(
                "could not read file pre-commit-phase2-output={:?}",
                params.pre_commit_phase2_output_path
            )
        })?;
    // It's just the `CommC` and `CommRLast` bytes concatenated. We use the bincode deserializer
    // just to be safe.
    let pre_commit_phase2_output: SealPreCommitOutput =
        deserialize(&pre_commit_phase2_output_bytes)?;

    let output = ReadPreCommitPhase2Output {
        comm_d: pre_commit_phase2_output.comm_d,
        comm_r: pre_commit_phase2_output.comm_r,
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
