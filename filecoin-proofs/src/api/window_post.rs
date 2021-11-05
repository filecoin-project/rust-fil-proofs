use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use filecoin_hashers::Hasher;
use bellperson::bls::{Bls12, Fr};
use bellperson::groth16;
use log::{info, trace};
use rayon::prelude::*;
use storage_proofs_core::{
    compound_proof::{self, CompoundProof},
    merkle::MerkleTreeTrait,
    parameter_cache::SRS_MAX_PROOFS_TO_AGGREGATE,
    multi_proof::MultiProof,
    sector::SectorId,
};
use sha2::{Digest, Sha256};
use storage_proofs_post::fallback::{
    self, FallbackPoSt, FallbackPoStCompound, PrivateSector, PublicSector,
};

use crate::{
    api::{as_safe_commitment, get_partitions_for_window_post, partition_vanilla_proofs},
    caches::{get_post_params, get_post_verifying_key, get_post_srs_key, get_post_srs_verifier_key},
    parameters::window_post_setup_params,
    types::{
        AggregateSnarkProof, ChallengeSeed, FallbackPoStSectorProof, PoStConfig, PrivateReplicaInfo, ProverId,
        PublicReplicaInfo, SnarkProof,
    },
    PoStType,
};

/// Generates a Window proof-of-spacetime with provided vanilla proofs.
pub fn generate_window_post_with_vanilla<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    vanilla_proofs: Vec<FallbackPoStSectorProof<Tree>>,
) -> Result<SnarkProof> {
    info!("generate_window_post_with_vanilla:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(vanilla_proofs.len(), &post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let partitions = partitions.unwrap_or(1);

    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let mut pub_sectors = Vec::with_capacity(vanilla_proofs.len());
    for vanilla_proof in &vanilla_proofs {
        pub_sectors.push(PublicSector {
            id: vanilla_proof.sector_id,
            comm_r: vanilla_proof.comm_r,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let partitioned_proofs = partition_vanilla_proofs(
        &post_config,
        &pub_params.vanilla_params,
        &pub_inputs,
        partitions,
        &vanilla_proofs,
    )?;

    let proof = FallbackPoStCompound::prove_with_vanilla(
        &pub_params,
        &pub_inputs,
        partitioned_proofs,
        &groth_params,
    )?;

    info!("generate_window_post_with_vanilla:finish");

    proof.to_vec()
}

/// Generates a Window proof-of-spacetime.
pub fn generate_window_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_window_post:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), &post_config);

    let sector_count = vanilla_params.sector_count;
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params::<Tree>(&post_config)?;

    let trees: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_window_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<_>>()?;

    let mut pub_sectors = Vec::with_capacity(sector_count);
    let mut priv_sectors = Vec::with_capacity(sector_count);

    for ((sector_id, replica), tree) in replicas.iter().zip(trees.iter()) {
        let comm_r = replica.safe_comm_r().with_context(|| {
            format!("generate_window_post: safe_comm_r failed: {:?}", sector_id)
        })?;
        let comm_c = replica.safe_comm_c();
        let comm_r_last = replica.safe_comm_r_last();

        pub_sectors.push(PublicSector {
            id: *sector_id,
            comm_r,
        });
        priv_sectors.push(PrivateSector {
            tree,
            comm_c,
            comm_r_last,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let proof = FallbackPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)?;

    info!("generate_window_post:finish");

    proof.to_vec()
}

/// Verifies a window proof-of-spacetime.
pub fn verify_window_post<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    prover_id: ProverId,
    proof: &[u8],
) -> Result<bool> {
    info!("verify_window_post:start");

    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), &post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("verify_window_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            Ok(PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let is_valid = {
        let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;
        let multi_proof = MultiProof::new_from_reader(partitions, proof, &verifying_key)?;

        FallbackPoStCompound::verify(
            &pub_params,
            &pub_inputs,
            &multi_proof,
            &fallback::ChallengeRequirements {
                minimum_challenge_count: post_config.challenge_count * post_config.sector_count,
            },
        )?
    };
    if !is_valid {
        return Ok(false);
    }

    info!("verify_window_post:finish");

    Ok(true)
}

pub fn aggregate_window_post_proofs<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomnesses: &[ChallengeSeed],
    commit_outputs: &[Vec<u8>],
    total_sector_count: usize,
) -> Result<AggregateSnarkProof> {
    info!("aggregate_window_post_proofs:start");

    ensure!(
        !commit_outputs.is_empty(),
        "cannot aggregate with empty outputs"
    );

    let partitions = get_partitions_for_window_post(total_sector_count, &post_config);
    let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;
    let mut proofs: Vec<_> =
        commit_outputs
            .iter()
            .try_fold(Vec::new(), |mut acc, commit_output| -> Result<_> {
                acc.extend(
                    MultiProof::new_from_reader(
                        partitions,
                        &commit_output[..],
                        &verifying_key,
                    )?
                    .circuit_proofs,
                );

                Ok(acc)
            })?;


    trace!(
        "aggregate_window_post_proofs called with {} commit_outputs containing {} proofs",
        commit_outputs.len(),
        proofs.len(),
    );

    let target_proofs_len = get_aggregate_target_len(proofs.len());
    ensure!(
        target_proofs_len > 1,
        "cannot aggregate less than two proofs"
    );
    trace!(
        "aggregate_seal_commit_proofs will pad proofs to target_len {}",
        target_proofs_len
    );

    // If we're not at the pow2 target, duplicate the last proof until we are.
    pad_proofs_to_target(&mut proofs, target_proofs_len)?;

    // Hash all of the seeds and comm_r's pair-wise into a digest for the aggregate proof method.
    let hashed_randomness: [u8; 32] = {
        let mut hasher = Sha256::new();
        for randomness in randomnesses.iter() {
            hasher.update(randomness);
        }
        hasher.finalize().into()
    };

    let srs_prover_key = get_post_srs_key::<Tree>(&post_config, proofs.len())?;
    let aggregate_proof = FallbackPoStCompound::<Tree>::aggregate_proofs(
        &srs_prover_key,
        &hashed_randomness,
        proofs.as_slice(),
    )?;
    let mut aggregate_proof_bytes = Vec::new();
    aggregate_proof.write(&mut aggregate_proof_bytes)?;

    info!("aggregate_seal_commit_proofs:finish");

    Ok(aggregate_proof_bytes)

}

pub fn verify_aggregate_window_post_proofs<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    prover_id: ProverId,
    aggregate_proof_bytes: AggregateSnarkProof,
    randomnesses: &[ChallengeSeed],
    replicas: &[BTreeMap<SectorId, PublicReplicaInfo>],
) -> Result<bool> {
    info!("verify aggregate window post proofs: start");

    let commit_inputs: Vec<Vec<Fr>> = replicas
        .par_iter()
        .zip(randomnesses.par_iter())
        .map(|(replica, randomness)| get_window_post_inputs::<Tree>(&post_config, replica, randomness, prover_id))
        .try_reduce(Vec::new, |mut acc, current| {
                acc.extend(current);
                Ok(acc)
            })?;

    let aggregate_proof = 
    groth16::aggregate::AggregateProof::read(std::io::Cursor::new(&aggregate_proof_bytes))?;

    let aggregated_proofs_len = aggregate_proof.tmipp.gipa.nproofs as usize;

    ensure!(aggregated_proofs_len != 0, "cannot verify zero proofs");
    ensure!(!commit_inputs.is_empty(), "cannot verify with empty inputs");

    trace!(
        "verify_aggregate_window_post_proofs called with len {}",
        aggregated_proofs_len,
    );

    ensure!(
        aggregated_proofs_len > 1,
        "cannot verify less than two proofs"
    );
    ensure!(
        aggregated_proofs_len == aggregated_proofs_len.next_power_of_two(),
        "cannot verify non-pow2 aggregate seal proofs"
    );

    let num_inputs = commit_inputs.len();
    let num_inputs_per_proof = get_aggregate_target_len(num_inputs) / aggregated_proofs_len;
    let target_inputs_len = aggregated_proofs_len * num_inputs_per_proof;
    ensure!(
        target_inputs_len % aggregated_proofs_len == 0,
        "invalid number of inputs provided",
    );

    trace!(
        "verify_aggregate_window_post_proofs got {} inputs with {} inputs per proof",
        num_inputs,
        target_inputs_len / aggregated_proofs_len,
    );

    // Pad public inputs if needed.
    let commit_inputs =
        pad_inputs_to_target(&commit_inputs, num_inputs_per_proof, target_inputs_len)?;

    let verifying_key = get_post_verifying_key::<Tree>(&post_config)?;
    let srs_verifier_key =
        get_post_srs_verifier_key::<Tree>(&post_config, aggregated_proofs_len)?;

    // Hash all of the seeds and comm_r's pair-wise into a digest for the aggregate proof method.
    let hashed_randomness: [u8; 32] = {
        let mut hasher = Sha256::new();
        for randomness in randomnesses.iter() {
            hasher.update(randomness);
        }
        hasher.finalize().into()
    };

    info!("start verifying aggregate proof");
    let result = FallbackPoStCompound::<Tree>::verify_aggregate_proofs(
        &srs_verifier_key,
        &verifying_key,
        &hashed_randomness,
        commit_inputs.as_slice(),
        &aggregate_proof,
    )?;
    info!("end verifying aggregate proof");

    info!("verify_aggregate_window_post_proofs:finish");

    Ok(result)
}

pub fn get_window_post_inputs<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
)-> anyhow::Result<Vec<Vec<Fr>>> {

    let randomness_safe = as_safe_commitment(&randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), &post_config);

    // let sector_count = vanilla_params.sector_count;
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r = replica.safe_comm_r().with_context(|| {
                format!("verify_window_post: safe_comm_r failed: {:?}", sector_id)
            })?;
            Ok(PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let partitions = <FallbackPoStCompound<Tree> as CompoundProof<
        FallbackPoSt<'_, Tree>,
        _,
    >>::partition_count(&pub_params);

    let inputs: Vec<_> = (0..partitions)
        .into_iter()
        .map(|k| {
            FallbackPoStCompound::<Tree>::generate_public_inputs(
                &pub_inputs,
                &pub_params.vanilla_params,
                Some(k),
            )
        })
        .collect::<Result<_>>()?;

    Ok(inputs)
    
}

/// Given a value, get one suitable for aggregation.
fn get_aggregate_target_len(len: usize) -> usize {
    if len == 1 {
        2
    } else {
        len.next_power_of_two()
    }
}

/// Given a list of proofs and a target_len, make sure that the proofs list is padded to the target_len size.
fn pad_proofs_to_target(proofs: &mut Vec<groth16::Proof<Bls12>>, target_len: usize) -> Result<()> {
    trace!(
        "pad_proofs_to_target target_len {}, proofs len {}",
        target_len,
        proofs.len()
    );
    ensure!(
        target_len >= proofs.len(),
        "target len must be greater than actual num proofs"
    );
    ensure!(
        proofs.last().is_some(),
        "invalid last proof for duplication"
    );

    let last = proofs
        .last()
        .expect("invalid last proof for duplication")
        .clone();
    let mut padding: Vec<groth16::Proof<Bls12>> = (0..target_len - proofs.len())
        .map(|_| last.clone())
        .collect();
    proofs.append(&mut padding);

    ensure!(
        proofs.len().next_power_of_two() == proofs.len(),
        "proof count must be a power of 2 for aggregation"
    );
    ensure!(
        proofs.len() <= SRS_MAX_PROOFS_TO_AGGREGATE,
        "proof count for aggregation is larger than the max supported value"
    );

    Ok(())
}

/// Given a list of public inputs and a target_len, make sure that the inputs list is padded to the target_len size.
fn pad_inputs_to_target(
    commit_inputs: &[Vec<Fr>],
    num_inputs_per_proof: usize,
    target_len: usize,
) -> Result<Vec<Vec<Fr>>> {
    ensure!(
        !commit_inputs.is_empty(),
        "cannot aggregate with empty public inputs"
    );

    let mut num_inputs = commit_inputs.len();
    let mut new_inputs = commit_inputs.to_owned();

    if target_len != num_inputs {
        ensure!(
            target_len > num_inputs,
            "target len must be greater than actual num inputs"
        );
        let duplicate_inputs = &commit_inputs[(num_inputs - num_inputs_per_proof)..num_inputs];

        trace!("padding inputs from {} to {}", num_inputs, target_len);
        while target_len != num_inputs {
            new_inputs.extend_from_slice(duplicate_inputs);
            num_inputs += num_inputs_per_proof;
        }
    }

    Ok(new_inputs)
}
