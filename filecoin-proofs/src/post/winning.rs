use anyhow::{ensure, Context, Result};
use log::*;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    hasher::Hasher,
    merkle::MerkleTreeTrait,
    multi_proof::MultiProof,
    sector::SectorId,
    settings,
};
use storage_proofs_post::fallback;

use crate::parameters::{get_post_params, get_post_verifying_key, winning_post_setup_params};
use crate::types::{
    ChallengeSeed, Commitment, FallbackPoStSectorProof, PoStConfig, PoStType, PrivateReplicaInfo,
    ProverId, PublicReplicaInfo, SnarkProof,
};
use crate::util::as_safe_commitment;

use super::partition_vanilla_proofs;

/// Generates a Winning proof-of-spacetime with provided vanilla proofs.
pub fn generate_with_vanilla<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof> {
    info!("generate_winning_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        post_config.sector_count == 1,
        "invalid Winning PoSt config -- sector_count must be 1"
    );
    ensure!(
        vanilla_proofs.len() == 1,
        "expected exactly one vanilla proof"
    );

    let vanilla_proof = &vanilla_proofs[0];

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(&post_config)?;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &vec![fallback::PublicSector {
            id: vanilla_proof.sector_id,
            comm_r: vanilla_proof.comm_r,
        }],
        k: None,
    };

    let partitions = match pub_params.partitions {
        Some(x) => x,
        None => 1,
    };

    let partitioned_proofs = partition_vanilla_proofs(
        &pub_params.vanilla_params,
        &pub_inputs,
        partitions,
        &vanilla_proofs,
    )?;

    let proof = fallback::FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        partitioned_proofs,
        &groth_params,
    )?;
    let proof = proof.to_vec()?;

    info!("generate_winning_post_with_vanilla:finish");

    Ok(proof)
}

/// Generates a Winning proof-of-spacetime.
pub fn generate<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PrivateReplicaInfo<Tree>)],
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_winning_post:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    ensure!(
        replicas.len() == post_config.sector_count,
        "invalid amount of replicas"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(&post_config)?;
    let param_sector_count = vanilla_params.sector_count;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let trees = replicas
        .iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_winning_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    let mut priv_sectors = Vec::with_capacity(param_sector_count);

    for _ in 0..param_sector_count {
        for ((sector_id, replica), tree) in replicas.iter().zip(trees.iter()) {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("generate_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            let comm_c = replica.safe_comm_c();
            let comm_r_last = replica.safe_comm_r_last();

            pub_sectors.push(fallback::PublicSector::<<Tree::Hasher as Hasher>::Domain> {
                id: *sector_id,
                comm_r,
            });
            priv_sectors.push(fallback::PrivateSector {
                tree,
                comm_c,
                comm_r_last,
            });
        }
    }

    let pub_inputs = fallback::PublicInputs::<<Tree::Hasher as Hasher>::Domain> {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let proof = fallback::FallbackPoStCompound::<Tree>::prove(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
    )?;
    let proof = proof.to_vec()?;

    info!("generate_winning_post:finish");

    Ok(proof)
}

/// Given some randomness and the length of available sectors, generates the challenged sector.
///
/// The returned values are indices in the range of `0..sector_set_size`, requiring the caller
/// to match the index to the correct sector.
pub fn generate_sector_challenge<Tree: MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    sector_set_size: u64,
    prover_id: Commitment,
) -> Result<Vec<u64>> {
    info!("generate_winning_post_sector_challenge:start");
    ensure!(sector_set_size != 0, "empty sector set is invalid");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let result = fallback::generate_sector_challenges(
        randomness_safe,
        post_config.sector_count,
        sector_set_size,
        prover_id_safe,
    );

    info!("generate_winning_post_sector_challenge:finish");

    result
}

/// Verifies a winning proof-of-spacetime.
///
/// The provided `replicas` must be the same ones as passed to `generate_winning_post`, and be based on
/// the indices generated by `generate_winning_post_sector_challenge`. It is the responsibility of the
/// caller to ensure this.
pub fn verify<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &[(SectorId, PublicReplicaInfo)],
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool> {
    info!("verify_winning_post:start");

    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );
    ensure!(
        post_config.sector_count == replicas.len(),
        "invalid amount of replicas provided"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = winning_post_setup_params(&post_config)?;
    let param_sector_count = vanilla_params.sector_count;

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<Tree>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;

    let mut pub_sectors = Vec::with_capacity(param_sector_count);
    for _ in 0..param_sector_count {
        for (sector_id, replica) in replicas.iter() {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("verify_winning_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            pub_sectors.push(fallback::PublicSector {
                id: *sector_id,
                comm_r,
            });
        }
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
        k: None,
    };

    let use_fil_blst = settings::SETTINGS
        .lock()
        .expect("use_fil_blst settings lock failure")
        .use_fil_blst;

    let is_valid = if use_fil_blst {
        info!("verify_winning_post: use_fil_blst=true");
        let verifying_key_path = post_config.get_cache_verifying_key_path::<Tree>()?;
        fallback::FallbackPoStCompound::verify_blst(
            &pub_params,
            &pub_inputs,
            &proof,
            proof.len() / 192,
            &fallback::ChallengeRequirements {
                minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
            },
            &verifying_key_path,
        )?
    } else {
        let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;

        let single_proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key)?;
        if single_proof.len() != 1 {
            return Ok(false);
        }

        fallback::FallbackPoStCompound::verify(
            &pub_params,
            &pub_inputs,
            &single_proof,
            &fallback::ChallengeRequirements {
                minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
            },
        )?
    };

    if !is_valid {
        return Ok(false);
    }

    info!("verify_winning_post:finish");

    Ok(true)
}
