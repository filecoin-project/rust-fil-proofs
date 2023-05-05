use std::cmp;
use std::fs::{File, OpenOptions};
use std::io::Write;

use anyhow::{ensure, Context, Result};
use ff::PrimeField;
use fil_proofs_bin::cli;
use filecoin_hashers::Domain;
use filecoin_proofs::ChunkIterator;
use fr32::bytes_into_fr;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_update::{
    constants::{h_default, TreeDDomain, TreeRDomain},
    phi,
    vanilla::Rhos,
};

#[derive(Debug, Deserialize, Serialize)]
struct UpdateEncodeParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// The path to the data that that should be put into the new sector.
    input_path: String,
    /// The number of bytes we want to encode.
    length: usize,
    /// That's the offset the stream is currently at in bytes.
    offset: usize,
    /// The path where the newly encoded data will be stored.
    output_path: String,
    /// Path to the sector key.
    sector_key_path: String,
    sector_size: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct UpdateEncodeOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

#[allow(clippy::too_many_arguments)]
fn update_encode(
    nodes_count: usize,
    comm_d: [u8; 32],
    comm_r: [u8; 32],
    input_path: String,
    sector_key_path: String,
    output_path: String,
    nodes_offset: usize,
    num_nodes: usize,
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

    let comm_d_domain = TreeDDomain::try_from_bytes(&comm_d[..])?;
    let comm_r_domain = TreeRDomain::try_from_bytes(&comm_r[..])?;
    let phi = phi(&comm_d_domain, &comm_r_domain);
    let h = h_default(nodes_count);
    let rhos = Rhos::new_range(&phi, h, nodes_count, nodes_offset, num_nodes);

    let bytes_length = num_nodes * NODE_SIZE;

    let input_iter = ChunkIterator::new(input_file);
    let sector_key_iter = ChunkIterator::new(sector_key_file);
    let chunk_size = input_iter.chunk_size();

    for (chunk_index, (input_chunk_result, sector_key_chunk_result)) in
        input_iter.zip(sector_key_iter).enumerate()
    {
        let chunk_offset = chunk_index * chunk_size;

        if chunk_offset > bytes_length {
            break;
        }

        let input_chunk = input_chunk_result?;
        let sector_key_chunk = sector_key_chunk_result?;

        // If the bytes that still need to be read is smaller then the chunk size, then use that
        // size.
        let current_chunk_size = cmp::min(bytes_length - chunk_offset, chunk_size);
        ensure!(
            current_chunk_size <= input_chunk.len(),
            "not enough bytes in input file={}",
            input_path
        );
        ensure!(
            current_chunk_size <= sector_key_chunk.len(),
            "not enough bytes in sector key file={}",
            sector_key_path
        );

        let output_reprs = (0..current_chunk_size)
            .step_by(NODE_SIZE)
            .map(|index| {
                // The absolute byte offset within the current sector
                let offset = (nodes_offset * NODE_SIZE) + chunk_offset + index;
                let rho = rhos.get(offset / NODE_SIZE);

                let sector_key_fr = bytes_into_fr(&sector_key_chunk[index..index + NODE_SIZE])?;
                let input_fr = bytes_into_fr(&input_chunk[index..index + NODE_SIZE])?;

                // This is the actual encoding step. Those operations happen on field elements.
                let output_fr = sector_key_fr + (input_fr * rho);
                Ok(output_fr.to_repr())
            })
            .collect::<Result<Vec<_>>>()?;

        output_file.write_all(&output_reprs.concat())?;
    }
    output_file.flush()?;

    Ok(())
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: UpdateEncodeParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    ensure!(
        params.length % NODE_SIZE == 0,
        "the length must be a multiple of 32 bytes"
    );
    ensure!(
        params.offset % NODE_SIZE == 0,
        "the offset must be a multiple of 32 bytes"
    );

    update_encode(
        params.sector_size as usize / NODE_SIZE,
        params.comm_d,
        params.comm_r,
        params.input_path,
        params.sector_key_path,
        params.output_path,
        params.offset / NODE_SIZE,
        params.length / NODE_SIZE,
    )?;
    let output = UpdateEncodeOutput::default();
    cli::print_stdout(output)?;

    Ok(())
}
