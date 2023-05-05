use std::{
    fs::{self, File},
    path::Path,
};

use anyhow::{Context, Result};
use bellperson::groth16;
use fil_proofs_bin::cli;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use sha2::{Digest, Sha256};
use storage_proofs_core::parameter_cache;

#[derive(Debug, Deserialize, Serialize)]
struct SnarkProofAggregateParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// The path to the file that contains the proofs to aggregate.
    input_path: String,
    num_proofs: usize,
    /// The path to the file the aggregated proof should be stored into.
    output_path: String,
    #[serde(with = "SerHex::<StrictPfx>")]
    seed: [u8; 32],
    /// Path to the Filecoin Groth16 parameter file the corresponds to the given sector size.
    srs_key_path: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct SnarkProofAggregateOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: SnarkProofAggregateParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let proof_bytes = fs::read(&params.input_path)
        .with_context(|| format!("failed to open proofs={:?}", params.input_path))?;
    let mut proofs = groth16::Proof::read_many(&proof_bytes, params.num_proofs)
        .context("failed to parse proofs")?;

    let target_proofs_len = filecoin_proofs::get_aggregate_target_len(proofs.len());
    assert!(
        target_proofs_len > 1,
        "cannot aggregate less than two proofs"
    );

    // If we're not at the pow2 target, duplicate the last proof until we are.
    filecoin_proofs::pad_proofs_to_target(&mut proofs, target_proofs_len)?;

    let hashed_seeds_and_comm_rs: [u8; 32] = {
        let mut hasher = Sha256::new();
        //for cur in seeds.iter().zip(comm_rs.iter()) {
        //let (seed, comm_r) = cur;
        hasher.update(params.seed);
        hasher.update(params.comm_r);
        //}
        hasher.finalize().into()
    };

    let srs_key = parameter_cache::read_cached_srs_key(Path::new(&params.srs_key_path))
        .with_context(|| format!("failed to read srs key={:?}", params.srs_key_path))?;
    let (srs_prover_key, _srs_verifer_key) = srs_key.specialize(target_proofs_len);

    let aggregated = groth16::aggregate::aggregate_proofs(
        &srs_prover_key,
        &hashed_seeds_and_comm_rs,
        proofs.as_slice(),
        groth16::aggregate::AggregateVersion::V2,
    )
    .context("aggregation failed")?;

    let file = File::create(&params.output_path).with_context(|| {
        format!(
            "failed to create aggregate proof file: {:?}",
            params.output_path,
        )
    })?;
    aggregated.write(file).with_context(|| {
        format!(
            "failed to write into aggregate proof file: {:?}",
            params.output_path,
        )
    })?;

    let output = SnarkProofAggregateOutput::default();
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
