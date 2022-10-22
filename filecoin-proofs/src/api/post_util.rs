use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{anyhow, ensure, Context, Result};
use bincode::deserialize;
use filecoin_hashers::Hasher;
use log::{debug, info};
use storage_proofs_core::{
    api_version::ApiVersion, cache_key::CacheKey, merkle::MerkleTreeTrait, proof::ProofScheme,
    sector::SectorId,
};
use storage_proofs_post::fallback::{
    self, generate_leaf_challenge, FallbackPoSt, PoStShape, SectorProof,
};

use crate::{
    api::as_safe_commitment,
    constants::DefaultPieceHasher,
    types::{
        ChallengeSeed, FallbackPoStSectorProof, PoStConfig, PrivateReplicaInfo, ProverId,
        TemporaryAux, VanillaProof,
    },
    PartitionSnarkProof, PoStType, SnarkProof, SINGLE_PARTITION_PROOF_LEN,
};

// Ensure that any associated cached data persisted is discarded.
pub fn clear_cache<Tree>(cache_dir: &Path) -> Result<()>
where
    Tree: MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    info!("clear_cache:start");

    let mut t_aux: TemporaryAux<Tree, DefaultPieceHasher<Tree::Field>> = {
        let f_aux_path = cache_dir.to_path_buf().join(CacheKey::TAux.to_string());
        let aux_bytes = fs::read(&f_aux_path)
            .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

        deserialize(&aux_bytes)
    }?;

    t_aux.set_cache_path(cache_dir);
    let result = TemporaryAux::<Tree, DefaultPieceHasher<Tree::Field>>::clear_temp(t_aux);

    info!("clear_cache:finish");

    result
}

// Ensure that any associated cached data persisted is discarded.
pub fn clear_caches<Tree>(replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>) -> Result<()>
where
    Tree: MerkleTreeTrait,
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    info!("clear_caches:start");

    for replica in replicas.values() {
        clear_cache::<Tree>(replica.cache_dir.as_path())?;
    }

    info!("clear_caches:finish");

    Ok(())
}

/// Generates the challenges per SectorId required for either a Window
/// proof-of-spacetime or a Winning proof-of-spacetime.
pub fn generate_fallback_sector_challenges<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    pub_sectors: &[SectorId],
    _prover_id: ProverId,
) -> Result<BTreeMap<SectorId, Vec<u64>>> {
    info!("generate_sector_challenges:start");
    ensure!(
        post_config.typ == PoStType::Window || post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let randomness_safe: <Tree::Hasher as Hasher>::Domain =
        as_safe_commitment(randomness, "randomness")?;

    let shape = match post_config.typ {
        PoStType::Window => PoStShape::Window,
        PoStType::Winning => PoStShape::Winning,
    };

    let public_params = fallback::PublicParams {
        sector_size: u64::from(post_config.sector_size),
        challenge_count: post_config.challenge_count,
        sector_count: post_config.sector_count,
        shape,
        api_version: post_config.api_version,
    };

    let mut sector_challenges: BTreeMap<SectorId, Vec<u64>> = BTreeMap::new();

    let num_sectors_per_chunk = post_config.sector_count;
    let partitions = match post_config.typ {
        PoStType::Window => {
            get_partitions_for_window_post(pub_sectors.len(), post_config).unwrap_or(1)
        }
        PoStType::Winning => 1,
    };

    for partition_index in 0..partitions {
        let sectors = pub_sectors
            .chunks(num_sectors_per_chunk)
            .nth(partition_index)
            .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;

        for (i, sector) in sectors.iter().enumerate() {
            let mut challenges = Vec::new();

            for n in 0..post_config.challenge_count {
                let challenge_index = match post_config.api_version {
                    ApiVersion::V1_0_0 | ApiVersion::V1_1_0 => {
                        (partition_index * post_config.sector_count + i)
                            * post_config.challenge_count
                            + n
                    }
                    _ => n,
                } as u64;

                let challenged_leaf = generate_leaf_challenge(
                    &public_params,
                    randomness_safe,
                    u64::from(*sector),
                    challenge_index,
                );
                challenges.push(challenged_leaf);
            }

            sector_challenges.insert(*sector, challenges);
        }
    }

    info!("generate_sector_challenges:finish");

    Ok(sector_challenges)
}

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

    let priv_sectors = vec![fallback::PrivateSector {
        tree,
        comm_c,
        comm_r_last,
    }];

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

// Partition a flat vector of vanilla sector proofs.  The post_config
// (PoSt) type is required in order to determine the proper shape of
// the returned partitioned proofs.
pub fn partition_vanilla_proofs<Tree: MerkleTreeTrait>(
    pub_params: &fallback::PublicParams,
    pub_inputs: &fallback::PublicInputs<<Tree::Hasher as Hasher>::Domain>,
    partition_count: usize,
    fallback_sector_proofs: &[FallbackPoStSectorProof<Tree>],
) -> Result<Vec<VanillaProof<Tree>>> {
    info!("partition_vanilla_proofs:start");
    let num_sectors_per_chunk = pub_params.sector_count;
    let mut partition_proofs = Vec::new();

    // Note that the partition proofs returned are shaped differently
    // based on which type of PoSt is being considered.
    let partition_proofs: Vec<_> = match pub_params.shape {
        PoStType::Window => {
            let num_sectors = pub_inputs.sectors.len();

            ensure!(
                num_sectors <= partition_count * num_sectors_per_chunk,
                "cannot prove the provided number of sectors: {} > {} * {}",
                num_sectors,
                partition_count,
                num_sectors_per_chunk,
            );

            ensure!(
                partition_count == 1,
                "Winning PoSt must be a single partition but got {} partitions",
                partition_count
            );

            for (j, sectors_chunk) in pub_inputs.sectors.chunks(num_sectors_per_chunk).enumerate() {
                let proof = single_partition_vanilla_proofs(
                    pub_params,
                    &fallback::PublicInputs {
                        randomness: pub_inputs.randomness,
                        prover_id: pub_inputs.prover_id,
                        sectors: sectors_chunk.to_vec(),
                        k: Some(j),
                    },
                    fallback_sector_proofs,
                )?;
                partition_proofs.push(proof);
            }
            partition_proofs
        }
        PoStType::Winning => {
            for (j, sectors_chunk) in fallback_sector_proofs
                .chunks(num_sectors_per_chunk)
                .enumerate()
            {
                let proof = single_partition_vanilla_proofs(
                    pub_params,
                    &fallback::FallbackPoSt::<Tree>::with_partition(pub_inputs.clone(), Some(j)),
                    sectors_chunk,
                )?;
                partition_proofs.push(proof);
            }
            partition_proofs
        }
    };

    info!("partition_vanilla_proofs:finish");

    ensure!(
        FallbackPoSt::<Tree>::verify_all_partitions(pub_params, pub_inputs, &partition_proofs)?,
        "partitioned vanilla proofs failed to verify"
    );

    Ok(partition_proofs)
}

pub(crate) fn get_partitions_for_window_post(
    total_sector_count: usize,
    post_config: &PoStConfig,
) -> Option<usize> {
    let partitions = (total_sector_count as f32 / post_config.sector_count as f32).ceil() as usize;

    if partitions > 1 {
        Some(partitions)
    } else {
        None
    }
}

pub fn single_partition_vanilla_proofs<Tree: MerkleTreeTrait>(
    pub_params: &fallback::PublicParams,
    pub_inputs: &fallback::PublicInputs<<Tree::Hasher as Hasher>::Domain>,
    fallback_sector_proofs: &[FallbackPoStSectorProof<Tree>],
) -> Result<VanillaProof<Tree>> {
    info!("single_partition_vanilla_proofs:start");
    ensure!(pub_inputs.k.is_some(), "must have a partition index");
    let partition_index = pub_inputs.k.expect("prechecked");

    debug!("processing partition: {}", partition_index);
    ensure!(
        pub_params.shape == PoStShape::Window || pub_params.shape == PoStShape::Winning,
        "invalid post config type"
    );

    let num_sectors_per_chunk = pub_params.sector_count;
    let num_sectors = pub_inputs.sectors.len();
    ensure!(
        num_sectors <= num_sectors_per_chunk,
        "can only prove a single partition"
    );

    // Note that the partition proofs returned are shaped differently
    // based on which type of PoSt is being considered.
    let partition_proof = match pub_params.shape {
        PoStType::Window => {
            let num_sectors_per_chunk = pub_params.sector_count;
            let sectors_chunk = &pub_inputs.sectors;
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

            fallback::Proof::<<Tree as MerkleTreeTrait>::Proof> {
                sectors: sector_proofs,
            }
        }
        PoStType::Winning => {
            // Sanity check incoming structure
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

            fallback::Proof::<<Tree as MerkleTreeTrait>::Proof> {
                sectors: sector_proofs,
            }
        }
    };

    info!("single_partition_vanilla_proofs:finish");

    ensure!(
        FallbackPoSt::<Tree>::verify(pub_params, pub_inputs, &partition_proof)?,
        "partitioned vanilla proofs failed to verify"
    );

    Ok(partition_proof)
}

pub fn merge_window_post_partition_proofs(
    mut proofs: Vec<PartitionSnarkProof>,
) -> Result<SnarkProof> {
    let mut proof = Vec::with_capacity(proofs.len() * SINGLE_PARTITION_PROOF_LEN);
    for p in proofs.iter_mut() {
        proof.append(&mut p.0);
    }

    Ok(proof)
}

pub fn get_num_partition_for_fallback_post(config: &PoStConfig, num_sectors: usize) -> usize {
    match config.typ {
        PoStType::Window => {
            let partitions = (num_sectors as f32 / config.sector_count as f32).ceil() as usize;
            if partitions > 1 {
                partitions
            } else {
                1
            }
        }
        PoStType::Winning => 1,
    }
}
