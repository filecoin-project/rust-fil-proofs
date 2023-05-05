//! Module for things related to command line interaction.

use std::io::{self, BufRead, BufReader, BufWriter, Write};

use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};

/// Parses a single line and returns the parsed data.
fn parse_line<R: BufRead, T: DeserializeOwned>(input: R) -> Result<T, serde_json::Error> {
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

/// Parses a single line of JSON from stdin and returns the parsed data.
pub fn parse_stdin<T: DeserializeOwned>() -> Result<T, serde_json::Error> {
    parse_line(BufReader::new(io::stdin()))
}

/// Outputs an object serialized to JSON to stdout.
pub fn print_stdout<S: Serialize>(data: S) -> Result<()> {
    print_line(&mut BufWriter::new(io::stdout()), data)
}
