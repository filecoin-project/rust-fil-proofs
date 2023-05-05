use std::fs::{File, OpenOptions};

use anyhow::{ensure, Context, Result};
use fil_proofs_bin::cli;
use filecoin_proofs::decode_from_range;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::util::NODE_SIZE;

#[derive(Debug, Deserialize, Serialize)]
struct UpdateDecodeParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// The path to the encoded sector.
    input_path: String,
    /// The number of bytes we want to decode.
    length: usize,
    /// That's the offset the stream is currently at in bytes.
    offset: usize,
    /// The path where the newly decoded data will be stored.
    output_path: String,
    /// Path to the sector key.
    sector_key_path: String,
    sector_size: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct UpdateDecodeOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

#[allow(clippy::too_many_arguments)]
fn update_decode(
    comm_d: [u8; 32],
    comm_r: [u8; 32],
    input_path: String,
    length: usize,
    file_offset: usize,
    output_path: String,
    sector_key_path: String,
    sector_size: u64,
) -> Result<()> {
    let input_file = File::open(&input_path)
        .with_context(|| format!("could not open input file={}", input_path))?;
    let sector_key_file = File::open(&sector_key_path)
        .with_context(|| format!("could not open secor key file={}", sector_key_path))?;
    let mut output_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&output_path)
        .with_context(|| format!("could not open output file={}", output_path))?;

    decode_from_range(
        sector_size as usize / NODE_SIZE,
        comm_d,
        comm_r,
        &input_file,
        &sector_key_file,
        &mut output_file,
        file_offset / NODE_SIZE,
        length / NODE_SIZE,
    )
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: UpdateDecodeParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    ensure!(
        params.length % NODE_SIZE == 0,
        "the length must be a multiple of 32 bytes"
    );
    ensure!(
        params.offset % NODE_SIZE == 0,
        "the offset must be a multiple of 32 bytes"
    );

    update_decode(
        params.comm_d,
        params.comm_r,
        params.input_path,
        params.length,
        params.offset,
        params.output_path,
        params.sector_key_path,
        params.sector_size,
    )?;
    let output = UpdateDecodeOutput::default();
    cli::print_stdout(output)?;

    Ok(())
}
