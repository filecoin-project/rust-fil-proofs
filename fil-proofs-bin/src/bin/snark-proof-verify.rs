use std::{fs, path::Path};

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
struct SnarkProofVerifyParameters {
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_d: [u8; 32],
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// The path to the file that contains the proofs to verify.
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
    /// Path to the Filecoin Groth16 parameter file the corresponds to the given sector size.
    verifying_key_path: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct SnarkProofVerifyOutput {
    verifies: bool,
}

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
    verifying_key_path: String,
) -> Result<bool> {
    let proof_bytes =
        fs::read(&input_path).with_context(|| format!("failed to open proofs={:?}", input_path))?;
    let proofs = groth16::Proof::read_many(&proof_bytes, num_partitions)
        .context("failed to parse proofs")?;
    let proofs_ref = proofs.iter().collect::<Vec<_>>();

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
        challenges: Challenges::new_interactive(num_challenges_per_partition),
        num_layers,
        api_version: ApiVersion::V1_2_0,
        // Even if the proofs come from the a synthetic porep, it doesn't matter for the SNARK,
        // henc we can leave the features section empty.
        api_features: Vec::new(),
    };

    let compound_setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: num_partitions,
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
    let verifying_key = parameter_cache::read_cached_verifying_key(Path::new(&verifying_key_path))
        .with_context(|| format!("failed to read verifying key={:?}", verifying_key_path))?;
    let prepared_verifying_key = groth16::prepare_verifying_key(&verifying_key);

    let verifies = groth16::verify_proofs_batch(
        &prepared_verifying_key,
        &mut OsRng,
        &proofs_ref[..],
        &inputs,
    )
    .context("verification failed")?;
    Ok(verifies)
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: SnarkProofVerifyParameters = cli::parse_stdin()?;
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
        params.verifying_key_path,
    )?;

    let output = SnarkProofVerifyOutput { verifies };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
