// Extract the proofs needed for PoRep out of a file full of Synthetoc PoRep proofs.

use std::fs::{self, File};

use anyhow::{Context, Result};
use fil_proofs_bin::cli;
use filecoin_hashers::poseidon::PoseidonHasher;
use filecoin_proofs::{with_shape, DefaultPieceHasher};
use log::info;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{merkle::MerkleTreeTrait, util::NODE_SIZE};
use storage_proofs_porep::stacked::SynthProofs;

#[derive(Debug, Deserialize, Serialize)]
struct MerkleProofsSynthExtractParameters {
    challenges: Vec<usize>,
    num_layers: usize,
    /// The path to the file the proofs should be stored into.
    output_path: String,
    sector_size: u64,
    synth_proofs_path: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct MerkleProofsSynthExtractOutput {
    // This is a hack to serialize a struct into an empty Object instead of null
    #[serde(skip_serializing)]
    _placeholder: (),
}

fn merkle_proofs<Tree: 'static + MerkleTreeTrait<Hasher = PoseidonHasher>>(
    challenges: Vec<usize>,
    num_layers: usize,
    sector_size: u64,
    synth_proofs_path: String,
) -> Result<Vec<u8>> {
    let mut file = File::open(&synth_proofs_path).with_context(|| {
        format!(
            "failed to open synthetic vanilla proofs file: {:?}",
            synth_proofs_path
        )
    })?;

    let sector_nodes = (sector_size as usize) / NODE_SIZE;
    let proofs = SynthProofs::read::<Tree, DefaultPieceHasher, _>(
        &mut file,
        sector_nodes,
        num_layers,
        challenges.into_iter(),
    )
    .with_context(|| {
        format!(
            "failed to read synthetic proofs from file: {:?}",
            synth_proofs_path,
        )
    })?;

    let mut proofs_bytes = Vec::new();
    SynthProofs::write(&mut proofs_bytes, &proofs)
        .expect("serializtion into vector always succeeds");
    Ok(proofs_bytes)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: MerkleProofsSynthExtractParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let proofs = with_shape!(
        params.sector_size,
        merkle_proofs,
        params.challenges,
        params.num_layers,
        params.sector_size,
        params.synth_proofs_path,
    )?;

    fs::write(params.output_path, proofs)?;

    let output = MerkleProofsSynthExtractOutput::default();
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
