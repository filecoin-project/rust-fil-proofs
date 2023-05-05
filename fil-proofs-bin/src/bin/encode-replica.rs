use std::fs::OpenOptions;
use std::io::{BufReader, ErrorKind, Read, Write};

use anyhow::{Context, Result};
use fil_proofs_bin::cli;
use filecoin_hashers::Domain;
use filecoin_proofs::DefaultPieceDomain;
use log::info;
use serde::{Deserialize, Serialize};
use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_porep::encode;

#[derive(Debug, Deserialize, Serialize)]
struct EncodeReplicaParameters {
    /// The file that should be encoded with the sector key.
    input_path: String,
    /// The path where the replica should be stored.
    replica_path: String,
    /// Path to the sector key used for encoding the replica.
    sector_key_path: String,
    //sector_size: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct EncodeReplicaOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: EncodeReplicaParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let input_file = OpenOptions::new()
        .read(true)
        .open(&params.input_path)
        .with_context(|| format!("failed to open input file: {}", params.input_path))?;
    let mut input_reader = BufReader::new(input_file);

    let sector_key_file = OpenOptions::new()
        .read(true)
        .open(&params.sector_key_path)
        .with_context(|| format!("failed to open sector key file: {}", params.sector_key_path))?;
    let mut sector_key_reader = BufReader::new(sector_key_file);

    let mut replica_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&params.replica_path)
        .with_context(|| format!("failed to open output file: {}", params.replica_path))?;

    loop {
        let mut key_buffer = vec![0; NODE_SIZE];
        let mut value_buffer = vec![0; NODE_SIZE];
        if let Err(error) = sector_key_reader.read_exact(&mut key_buffer) {
            match error.kind() {
                // Loop until the end of the file was reached.
                ErrorKind::UnexpectedEof => break,
                _ => return Err(error)?,
            };
        }
        input_reader.read_exact(&mut value_buffer)?;
        let key = DefaultPieceDomain::try_from_bytes(&key_buffer)?;
        let value = DefaultPieceDomain::try_from_bytes(&value_buffer)?;
        let encoded = encode::encode(key, value);
        replica_file.write_all(encoded.as_ref())?;
    }

    let output = EncodeReplicaOutput::default();
    cli::print_stdout(output)?;

    Ok(())
}
