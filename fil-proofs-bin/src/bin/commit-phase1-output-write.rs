use std::fs::{self, File};

use anyhow::{Context, Result};
use fil_proofs_bin::cli;
use filecoin_proofs::{with_shape, DefaultPieceHasher, SealCommitPhase1Output};
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{merkle::MerkleTreeTrait, util::NODE_SIZE};
use storage_proofs_porep::stacked::SynthProofs;

#[derive(Debug, Deserialize, Serialize)]
struct CommitPhase1OutputWriteParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// Total number of challenges.
    num_challenges: usize,
    num_layers: usize,
    num_partitions: usize,
    /// The file to write the binary encoded commit phase1 output into.
    output_path: String,
    /// The file that contains the merkle proofs.
    porep_proofs_path: String,
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
    sector_size: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    seed: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    ticket: [u8; 32],
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct CommitPhase1OutputWriteOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

#[allow(clippy::too_many_arguments)]
fn serialize_commit_phase1_output<Tree: MerkleTreeTrait>(
    comm_d: [u8; 32],
    comm_r: [u8; 32],
    num_challenges: usize,
    num_layers: usize,
    num_partitions: usize,
    porep_proofs_path: String,
    replica_id: [u8; 32],
    sector_size: u64,
    seed: [u8; 32],
    ticket: [u8; 32],
) -> Result<Vec<u8>> {
    assert_eq!(num_challenges % num_partitions, 0);

    let mut file = File::open(&porep_proofs_path)
        .with_context(|| format!("failed to open porep proofs={:?}", porep_proofs_path))?;

    let sector_nodes = (sector_size as usize) / NODE_SIZE;
    let proofs = SynthProofs::read::<Tree, DefaultPieceHasher, _>(
        &mut file,
        sector_nodes,
        num_layers,
        0..num_challenges,
    )
    .with_context(|| format!("failed to read porrep proofs={:?}", porep_proofs_path,))?;
    let vanilla_proofs = proofs
        .chunks_exact(num_challenges / num_partitions)
        .map(|chunk| chunk.to_vec())
        .collect();

    let commit_phase1_output = SealCommitPhase1Output {
        vanilla_proofs,
        comm_r,
        comm_d,
        replica_id: replica_id.into(),
        seed,
        ticket,
    };

    let commit_phase1_output_bytes = bincode::serialize(&commit_phase1_output)?;
    Ok(commit_phase1_output_bytes)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: CommitPhase1OutputWriteParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let commit_phase1_output = with_shape!(
        params.sector_size,
        serialize_commit_phase1_output,
        params.comm_d,
        params.comm_r,
        params.num_challenges,
        params.num_layers,
        params.num_partitions,
        params.porep_proofs_path,
        params.replica_id,
        params.sector_size,
        params.seed,
        params.ticket,
    )?;

    fs::write(&params.output_path, commit_phase1_output)?;

    let output = CommitPhase1OutputWriteOutput::default();
    cli::print_stdout(output)?;

    Ok(())
}
