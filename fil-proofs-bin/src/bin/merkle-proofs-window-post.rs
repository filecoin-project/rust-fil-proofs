// Creates the merkle proofs out of the given challenges. This is the same binary for Interactive
// and Non-interactive PoReps. Synthetic PoReps have a different (two phases) approach.

use std::{fs, marker::PhantomData, path::{Path, PathBuf}};

use anyhow::{Context, Result};
use fil_proofs_bin::cli;
use filecoin_hashers::sha256::Sha256Hasher;
use filecoin_proofs::{with_shape, DefaultPieceHasher, DRG_DEGREE, EXP_DEGREE, types};
use generic_array::typenum::Unsigned;
use log::info;
use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_core::{
    api_version::ApiVersion, cache_key::CacheKey, merkle::{MerkleProofTrait, MerkleTreeTrait}, util::NODE_SIZE,
};
use storage_proofs_porep::stacked::{
    Labels, PublicInputs, StackedBucketGraph, StackedDrg, SynthProofs, Tau, TemporaryAux,
    TemporaryAuxCache, BINARY_ARITY,
};
use storage_proofs_post::fallback::{self, Proof, MerkleProofs};

/// Note that `comm_c` and `comm_d` are not strictly needed as they could be read from the
/// generated trees. Though they are passed in for sanity checking.
#[derive(Debug, Deserialize, Serialize)]
struct MerkleProofsWindowPostParameters {
    challenges: Vec<u64>,
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r_last: [u8; 32],
    /// The directory where the TreeRLast files are stored.
    input_dir: String,
    /// Path to the replica file.
    replica_path: String,
    /// The sector ID.
    sector_id: u64,
    /// Sector size is used to calculate the number of nodes.
    sector_size: u64,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct MerkleProofsWindowPostOutput {
    proofs: String,
}


/// Returns the inclusion proofs as JSON.
#[allow(clippy::too_many_arguments)]
fn merkle_proofs<Tree: 'static + MerkleTreeTrait>(
    challenges: Vec<u64>,
    comm_r_last: [u8; 32],
    input_dir: String,
    replica_path: String,
    sector_id: u64,
    sector_size: u64,
//) -> Result<Vec<MerkleProof<Proof>>> {
//) -> Result<MerkleProofs<Tree::Proof>> {
) -> Result<String> {
    let tree = types::merkle_tree::<Tree>(sector_size.into(), Path::new(&input_dir), Path::new(&replica_path)).unwrap();
    let inclusion_proofs =
        fallback::inclusion_proofs::<Tree>(sector_id.into(), &tree, &challenges, comm_r_last.into()).with_context(|| {
            format!(
                "generate_single_vanilla_proof: vanilla_proof failed: {:?}",
                sector_id
            )
        })?;

    let json = serde_json::to_string(&inclusion_proofs).unwrap();

////GO ON HERE and think about what this call should actually return. probaly something serialized written to disk. this would then be taken by anoher binary, that does the snark with calling:
//
//   let proof = generate_winning_post_with_vanilla::<Tree>(
//        &config,
//        &randomness,
//        prover_id,
//        vanilla_proofs,
//    )?;

    Ok(json)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: MerkleProofsWindowPostParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let proofs = with_shape!(
        params.sector_size,
        merkle_proofs,
        params.challenges,
        params.comm_r_last,
        params.input_dir,
        params.replica_path,
        params.sector_size,
        params.sector_id,
    )?;

    let output = MerkleProofsWindowPostOutput { proofs };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
