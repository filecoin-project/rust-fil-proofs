use std::io::{self, BufRead, BufReader, BufWriter, Write};

use anyhow::Result;
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

/// Parses a single line and returns the parsed parameters.
fn parse_line<R: BufRead>(input: R) -> Result<CommRParameters, serde_json::Error> {
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

    // comm_r = H(comm_c || comm_r_last)
    let comm_r = PoseidonFunction::hash2(&params.comm_c.into(), &params.comm_r_last.into());

    let output = CommROutput {
        comm_r: comm_r.into(),
    };
    info!("{:?}", output);
    print_line(&mut BufWriter::new(io::stdout()), output)?;

    Ok(())
}
