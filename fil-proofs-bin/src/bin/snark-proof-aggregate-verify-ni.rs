use std::{fs::File, path::Path};

use anyhow::{Context, Result};
use bellperson::groth16;
use fil_proofs_bin::cli;
use filecoin_hashers::sha256::Sha256Hasher;
use filecoin_proofs::{with_shape, DefaultPieceHasher, DRG_DEGREE, EXP_DEGREE};
use log::info;
use rand::rngs::OsRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    api_version::ApiVersion,
    compound_proof::{self, CompoundProof},
    merkle::MerkleTreeTrait,
    parameter_cache,
    util::NODE_SIZE,
};
use storage_proofs_porep::stacked::{
    Challenges, PublicInputs, SetupParams, StackedCompound, StackedDrg, Tau,
};

#[derive(Debug, Deserialize, Serialize)]
struct SnarkProofAggregateVerifyNiParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// The path to the file that contains the aggregated proofs to verify.
    input_path: String,
    num_challenges_per_partition: usize,
    num_layers: usize,
    num_partitions: usize,
    #[serde(with = "SerHex::<StrictPfx>")]
    porep_id: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    replica_id: [u8; 32],
    sector_size: u64,
    #[serde(with = "SerHex::<StrictPfx>")]
    seed: [u8; 32],
    /// Path to the SRS verifier key (it's the same file as for the prover key).
    srs_key_path: String,
    /// Path to the Filecoin Groth16 parameter file the corresponds to the given sector size.
    verifying_key_path: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct SnarkProofAggregateVerifyNiOutput {
    verifies: bool,
}

// This code is very similar to `filecoin_proofs::api::verify_aggregate_seal_commit_proofs`.
#[allow(clippy::too_many_arguments)]
fn snark_proof_verify<Tree: 'static + MerkleTreeTrait>(
    comm_d: [u8; 32],
    comm_r: [u8; 32],
    input_path: String,
    num_challenges_per_partition: usize,
    num_layers: usize,
    num_partitions: usize,
    porep_id: [u8; 32],
    replica_id: [u8; 32],
    sector_size: u64,
    seed: [u8; 32],
    srs_key_path: String,
    verifying_key_path: String,
) -> Result<bool> {
    //let proof_bytes =
    //    fs::read(&input_path).with_context(|| format!("failed to open proofs={:?}", input_path))?;
    let proof_file = File::open(&input_path)
        .with_context(|| format!("failed to open proofs={:?}", input_path))?;
    let proof = groth16::aggregate::AggregateProof::read(&proof_file)
        .context("failed to parse aggregate proof")?;

    let public_inputs = PublicInputs {
        replica_id: replica_id.into(),
        tau: Some(Tau {
            comm_d: comm_d.into(),
            comm_r: comm_r.into(),
        }),
        k: None,
        seed: Some(seed),
    };

    let sector_nodes = (sector_size as usize) / NODE_SIZE;
    let vanilla_params = SetupParams {
        nodes: sector_nodes,
        degree: DRG_DEGREE,
        expansion_degree: EXP_DEGREE,
        porep_id,
        challenges: Challenges::new_non_interactive(num_challenges_per_partition),
        num_layers,
        api_version: ApiVersion::V1_2_0,
        // Even if the proofs come from the a synthetic porep, it doesn't matter for the SNARK,
        // henc we can leave the features section empty.
        api_features: Vec::new(),
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: Some(num_partitions),
        priority: false,
    };

    let vanilla_public_params = <StackedCompound<Tree, DefaultPieceHasher> as CompoundProof<
        StackedDrg<'_, Tree, DefaultPieceHasher>,
        _,
    >>::setup(&compound_setup_params)?;

    let inputs: Vec<_> = (0..num_partitions)
        .into_par_iter()
        .map(|k| {
            StackedCompound::<Tree, Sha256Hasher>::generate_public_inputs(
                &public_inputs,
                &vanilla_public_params.vanilla_params,
                Some(k),
            )
        })
        .collect::<Result<_>>()?;

    let aggregated_proofs_len = proof.tmipp.gipa.nproofs as usize;
    let num_inputs = inputs.len();
    let num_inputs_per_proof =
        filecoin_proofs::get_aggregate_target_len(num_inputs) / aggregated_proofs_len;
    let target_inputs_len = aggregated_proofs_len * num_inputs_per_proof;
    assert_eq!(
        target_inputs_len % aggregated_proofs_len,
        0,
        "invalid number of inputs provided"
    );

    // Pad public inputs if needed.
    let commit_inputs =
        filecoin_proofs::pad_inputs_to_target(&inputs, num_inputs_per_proof, target_inputs_len)?;

    let verifying_key = parameter_cache::read_cached_verifying_key(Path::new(&verifying_key_path))
        .with_context(|| format!("failed to read verifying key={:?}", verifying_key_path))?;
    let prepared_verifying_key = groth16::prepare_verifying_key(&verifying_key);

    let srs_key = parameter_cache::read_cached_srs_key(Path::new(&srs_key_path))
        .with_context(|| format!("failed to read srs key={:?}", srs_key_path))?;
    let (_srs_prover_key, srs_verifer_key) = srs_key.specialize(target_inputs_len);

    let hashed_seeds_and_comm_rs: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(comm_r);
        hasher.finalize().into()
    };

    let verifies = groth16::aggregate::verify_aggregate_proof(
        &srs_verifer_key,
        &prepared_verifying_key,
        OsRng,
        commit_inputs.as_slice(),
        &proof,
        &hashed_seeds_and_comm_rs,
        groth16::aggregate::AggregateVersion::V2,
    )
    .context("verification failed")?;
    Ok(verifies)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: SnarkProofAggregateVerifyNiParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let verifies = with_shape!(
        params.sector_size,
        snark_proof_verify,
        params.comm_d,
        params.comm_r,
        params.input_path,
        params.num_challenges_per_partition,
        params.num_layers,
        params.num_partitions,
        params.porep_id,
        params.replica_id,
        params.sector_size,
        params.seed,
        params.srs_key_path,
        params.verifying_key_path,
    )?;

    let output = SnarkProofAggregateVerifyNiOutput { verifies };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
