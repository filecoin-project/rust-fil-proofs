use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use blstrs::Scalar as Fr;
use filecoin_hashers::Domain;
use filecoin_proofs::{
    commitment_from_fr, get_base_tree_leafs, get_base_tree_size, DefaultBinaryTree,
    DefaultPieceDomain,
};
use log::{info, trace};
use merkletree::store::StoreConfig;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    cache_key::CacheKey,
    merkle::{create_base_merkle_tree, BinaryMerkleTree},
    util::{default_rows_to_discard, NODE_SIZE},
};
use storage_proofs_porep::{encode, stacked::BINARY_ARITY};

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

/// Parses a single line and returns the parsed parameters.
fn parse_line<'a, R: BufRead, T: DeserializeOwned>(input: R) -> Result<T, serde_json::Error> {
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

    let params: EncodeReplicaParameters = parse_line(BufReader::new(io::stdin()))?;
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
    print_line(&mut BufWriter::new(io::stdout()), output)?;

    Ok(())
}
