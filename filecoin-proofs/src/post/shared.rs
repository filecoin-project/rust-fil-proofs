use std::collections::BTreeMap;

use anyhow::{anyhow, ensure, Context, Result};
use log::{info, trace};
use storage_proofs_core::{
    hasher::Hasher, merkle::MerkleTreeTrait, proof::ProofScheme, sector::SectorId,
};
use storage_proofs_post::fallback::{self, SectorProof};

use crate::{
    types::{
        ChallengeSeed, FallbackPoStSectorProof, PoStConfig, PoStType, PrivateReplicaInfo, ProverId,
        VanillaProof,
    },
    util::as_safe_commitment,
};

/// Generates a single vanilla proof required for either Window proof-of-spacetime
/// or Winning proof-of-spacetime.
pub fn generate_single_vanilla_proof<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    sector_id: SectorId,
    replica: &PrivateReplicaInfo<Tree>,
    challenges: &[u64],
) -> Result<FallbackPoStSectorProof<Tree>> {
    info!("generate_single_vanilla_proof:start: {:?}", sector_id);

    let tree = &replica
        .merkle_tree(post_config.sector_size)
        .with_context(|| {
            format!(
                "generate_single_vanilla_proof: merkle_tree failed: {:?}",
                sector_id
            )
        })?;
    let comm_r = replica.safe_comm_r().with_context(|| {
        format!(
            "generate_single_vanilla_poof: safe_comm_r failed: {:?}",
            sector_id
        )
    })?;
    let comm_c = replica.safe_comm_c();
    let comm_r_last = replica.safe_comm_r_last();

    let mut priv_sectors = Vec::with_capacity(1);
    priv_sectors.push(fallback::PrivateSector {
        tree,
        comm_c,
        comm_r_last,
    });

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let vanilla_proof =
        fallback::vanilla_proof(sector_id, &priv_inputs, challenges).with_context(|| {
            format!(
                "generate_single_vanilla_proof: vanilla_proof failed: {:?}",
                sector_id
            )
        })?;

    info!("generate_single_vanilla_proof:finish: {:?}", sector_id);

    Ok(FallbackPoStSectorProof {
        sector_id,
        comm_r,
        vanilla_proof,
    })
}

/// Partition a flat vector of vanilla sector proofs.  The post_config
/// (PoSt) type is required in order to determine the proper shape of
/// the returned partitioned proofs.
pub fn partition_vanilla_proofs<Tree: MerkleTreeTrait>(
    pub_params: &fallback::PublicParams,
    pub_inputs: &fallback::PublicInputs<<Tree::Hasher as Hasher>::Domain>,
    partition_count: usize,
    fallback_sector_proofs: &[FallbackPoStSectorProof<Tree>],
) -> Result<Vec<VanillaProof<Tree>>> {
    info!("partition_vanilla_proofs:start");

    // Note that the partition proofs returned are shaped differently
    // based on which type of PoSt is being considered.
    let partition_proofs: Vec<_> = match pub_params.shape {
        PoStType::Window => {
            let num_sectors_per_chunk = pub_params.sector_count;
            let num_sectors = pub_inputs.sectors.len();

            ensure!(
                num_sectors <= partition_count * num_sectors_per_chunk,
                "cannot prove the provided number of sectors: {} > {} * {}",
                num_sectors,
                partition_count,
                num_sectors_per_chunk,
            );

            let mut partition_proofs = Vec::new();

            for (j, sectors_chunk) in pub_inputs.sectors.chunks(num_sectors_per_chunk).enumerate() {
                trace!("processing partition {}", j);

                let mut sector_proofs = Vec::with_capacity(num_sectors_per_chunk);

                for pub_sector in sectors_chunk.iter() {
                    let cur_proof = fallback_sector_proofs
                        .iter()
                        .find(|&proof| proof.sector_id == pub_sector.id)
                        .expect("failed to locate sector proof");

                    // Note: Window post requires all inclusion proofs (based on the challenge
                    // count per sector) per sector proof.
                    sector_proofs.extend(cur_proof.vanilla_proof.sectors.clone());
                }

                // If there were less than the required number of sectors provided, we duplicate the last one
                // to pad the proof out, such that it works in the circuit part.
                while sector_proofs.len() < num_sectors_per_chunk {
                    sector_proofs.push(sector_proofs[sector_proofs.len() - 1].clone());
                }

                partition_proofs.push(fallback::Proof::<<Tree as MerkleTreeTrait>::Proof> {
                    sectors: sector_proofs,
                });
            }
            partition_proofs
        }
        PoStType::Winning => {
            // TODO: where is this defined?
            // pub_params.ensure_valid();

            ensure!(
                partition_count == 1,
                "Winning PoSt must be a single partition but got {} partitions",
                partition_count
            );
            ensure!(
                pub_inputs.sectors.len() == 1,
                "Winning PoSt must cover a single sector but {} sectors were provided",
                pub_inputs.sectors.len()
            );
            ensure!(
                fallback_sector_proofs.len() == 1,
                "Winning PoSt must cover a single sector but {} proofs were provided",
                fallback_sector_proofs.len()
            );

            let vanilla_proof_sectors = &fallback_sector_proofs[0].vanilla_proof.sectors;

            ensure!(
                vanilla_proof_sectors.len() == 1,
                "invalid number of sector proofs for Winning PoSt"
            );

            let vanilla_sector_proof = &vanilla_proof_sectors[0];
            let inclusion_proofs = vanilla_sector_proof.inclusion_proofs();

            // Unroll inclusions proofs from the single provided sector_proof (per partition)
            // into individual sector proofs, required for winning post.
            let sector_proofs = inclusion_proofs
                .iter()
                .map(|proof| SectorProof {
                    inclusion_proofs: vec![proof.clone()],
                    comm_c: vanilla_sector_proof.comm_c,
                    comm_r_last: vanilla_sector_proof.comm_r_last,
                })
                .collect::<Vec<_>>();

            let partition_proof = fallback::Proof::<<Tree as MerkleTreeTrait>::Proof> {
                sectors: sector_proofs,
            };

            vec![partition_proof]
        }
    };

    info!("partition_vanilla_proofs:finish");

    ensure!(
        fallback::FallbackPoSt::<Tree>::verify_all_partitions(
            pub_params,
            pub_inputs,
            &partition_proofs
        )?,
        "partitioned vanilla proofs failed to verify"
    );

    Ok(partition_proofs)
}

pub(crate) fn get_partitions(total_sector_count: usize, post_config: &PoStConfig) -> Option<usize> {
    let partitions = (total_sector_count as f32 / post_config.sector_count as f32).ceil() as usize;

    if partitions > 1 {
        Some(partitions)
    } else {
        None
    }
}

/// Generates the challenges per SectorId required for either a Window
/// proof-of-spacetime or a Winning proof-of-spacetime.
pub fn generate_fallback_sector_challenges<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    pub_sectors: &[SectorId],
    _prover_id: ProverId,
    shape: fallback::PoStShape,
) -> Result<BTreeMap<SectorId, Vec<u64>>> {
    info!("generate_sector_challenges:start");
    ensure!(
        post_config.typ == PoStType::Window || post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;

    let public_params = fallback::PublicParams {
        sector_size: u64::from(post_config.sector_size),
        challenge_count: post_config.challenge_count,
        sector_count: post_config.sector_count,
        shape,
    };

    let mut sector_challenges: BTreeMap<SectorId, Vec<u64>> = BTreeMap::new();

    let num_sectors_per_chunk = post_config.sector_count;
    let partitions = match post_config.typ {
        PoStType::Window => match get_partitions(pub_sectors.len(), &post_config) {
            Some(x) => x,
            None => 1,
        },
        PoStType::Winning => 1,
    };

    for partition_index in 0..partitions {
        let sectors = pub_sectors
            .chunks(num_sectors_per_chunk)
            .nth(partition_index)
            .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;

        for sector in sectors.iter() {
            let challenges = fallback::generate_leaf_challenges(
                &public_params,
                randomness_safe,
                u64::from(*sector),
                post_config.challenge_count,
            );

            sector_challenges.insert(*sector, challenges);
        }
    }

    info!("generate_sector_challenges:finish");

    Ok(sector_challenges)
}
