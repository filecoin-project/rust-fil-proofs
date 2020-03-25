use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use bincode::deserialize;
use log::{info, trace};
use merkletree::merkle::get_merkle_tree_leafs;
use merkletree::store::{ExternalReader, LevelCacheStore, StoreConfig};
use paired::bls12_381::Bls12;
use rayon::prelude::*;
use storage_proofs::cache_key::CacheKey;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::fr32::bytes_into_fr;
use storage_proofs::hasher::Hasher;
use storage_proofs::merkle::OctLCMerkleTree;
use storage_proofs::multi_proof::MultiProof;
use storage_proofs::post::election;
pub use storage_proofs::post::election::Candidate;
use storage_proofs::post::election::ElectionPoStCompound;
use storage_proofs::post::fallback;
use storage_proofs::proof::NoRequirements;
use storage_proofs::sector::*;

use crate::api::util::{as_safe_commitment, get_tree_size};
use crate::caches::{get_post_params, get_post_verifying_key};
use crate::constants::DefaultTreeHasher;
use crate::parameters::{
    election_post_setup_params, window_post_setup_params, winning_post_setup_params,
};
use crate::types::{
    ChallengeSeed, Commitment, LCTree, PersistentAux, PoStConfig, ProverId, TemporaryAux, OCT_ARITY,
};
use crate::PoStType;

/// The minimal information required about a replica, in order to be able to generate
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivateReplicaInfo {
    /// Path to the replica.
    replica: PathBuf,
    /// The replica commitment.
    comm_r: Commitment,
    /// Persistent Aux.
    aux: PersistentAux,
    /// Contains sector-specific (e.g. merkle trees) assets
    cache_dir: PathBuf,
}

impl std::cmp::Ord for PrivateReplicaInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl std::cmp::PartialOrd for PrivateReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PrivateReplicaInfo {
    pub fn new(replica: PathBuf, comm_r: Commitment, cache_dir: PathBuf) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

        let aux = {
            let mut aux_bytes = vec![];
            let f_aux_path = cache_dir.join(CacheKey::PAux.to_string());
            let mut f_aux = File::open(&f_aux_path)
                .with_context(|| format!("could not open path={:?}", f_aux_path))?;
            f_aux
                .read_to_end(&mut aux_bytes)
                .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

            deserialize(&aux_bytes)
        }?;

        ensure!(replica.exists(), "Sealed replica does not exist");

        Ok(PrivateReplicaInfo {
            replica,
            comm_r,
            aux,
            cache_dir,
        })
    }

    pub fn cache_dir_path(&self) -> &Path {
        self.cache_dir.as_path()
    }

    pub fn replica_path(&self) -> &Path {
        self.replica.as_path()
    }

    pub fn safe_comm_r(&self) -> Result<<DefaultTreeHasher as Hasher>::Domain> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }

    pub fn safe_comm_c(&self) -> Result<<DefaultTreeHasher as Hasher>::Domain> {
        Ok(self.aux.comm_c)
    }

    pub fn safe_comm_r_last(&self) -> Result<<DefaultTreeHasher as Hasher>::Domain> {
        Ok(self.aux.comm_r_last)
    }

    /// Generate the merkle tree of this particular replica.
    pub fn merkle_tree(&self, tree_size: usize, tree_leafs: usize) -> Result<LCTree> {
        trace!(
            "post: tree size {}, tree leafs {}, cached above base {}",
            tree_size,
            tree_leafs,
            StoreConfig::default_cached_above_base_layer(tree_leafs, OCT_ARITY)
        );
        let mut config = StoreConfig::new(
            self.cache_dir_path(),
            CacheKey::CommRLastTree.to_string(),
            StoreConfig::default_cached_above_base_layer(tree_leafs, OCT_ARITY),
        );
        config.size = Some(tree_size);

        let tree_r_last_store: LevelCacheStore<<DefaultTreeHasher as Hasher>::Domain, _> =
            LevelCacheStore::new_from_disk_with_reader(
                tree_size,
                OCT_ARITY,
                &config,
                ExternalReader::new_from_path(&self.replica_path().to_path_buf())?,
            )?;
        let tree_r_last = OctLCMerkleTree::from_data_store(tree_r_last_store, tree_leafs)?;

        Ok(tree_r_last)
    }
}

/// The minimal information required about a replica, in order to be able to verify
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicReplicaInfo {
    /// The replica commitment.
    comm_r: Commitment,
}

impl std::cmp::Ord for PublicReplicaInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl std::cmp::PartialOrd for PublicReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PublicReplicaInfo {
    pub fn new(comm_r: Commitment) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
        Ok(PublicReplicaInfo { comm_r })
    }

    pub fn safe_comm_r(&self) -> Result<<DefaultTreeHasher as Hasher>::Domain> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }
}

// Ensure that any associated cached data persisted is discarded.
pub fn clear_cache(cache_dir: &Path) -> Result<()> {
    let t_aux = {
        let mut aux_bytes = vec![];
        let f_aux_path = cache_dir.to_path_buf().join(CacheKey::TAux.to_string());
        let mut f_aux = File::open(&f_aux_path)
            .with_context(|| format!("could not open path={:?}", f_aux_path))?;
        f_aux
            .read_to_end(&mut aux_bytes)
            .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

        deserialize(&aux_bytes)
    }?;

    TemporaryAux::clear_temp(t_aux)
}

// Ensure that any associated cached data persisted is discarded.
pub fn clear_caches(replicas: &BTreeMap<SectorId, PrivateReplicaInfo>) -> Result<()> {
    for replica in replicas.values() {
        clear_cache(replica.cache_dir_path())?;
    }

    Ok(())
}

/// Generates proof-of-spacetime candidates for ElectionPoSt.
///
/// # Arguments
///
/// * `post_config` - post config that contains the sector size of each sector that we are
/// generating this post for.
/// * `randomness` - randomness used to generate sector challenges.
/// * `challenge_count` - the number sector challenges in this post.
/// * `replicas` - each sector's sector-id and associated replica info.
/// * `prover_id` - the prover-id that is generating this post.
pub fn generate_candidates(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    challenge_count: u64,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<Candidate>> {
    info!("generate_candidates:start");

    ensure!(!replicas.is_empty(), "Replicas must not be empty");
    ensure!(challenge_count > 0, "Challenge count must be > 0");

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "randomness")?;

    let vanilla_params = election_post_setup_params(&post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: false,
    };
    let public_params: compound_proof::PublicParams<election::ElectionPoSt<DefaultTreeHasher>> =
        ElectionPoStCompound::setup(&setup_params)?;

    let sector_count = replicas.len() as u64;
    ensure!(sector_count > 0, "Must supply at least one replica");

    let sectors = replicas.keys().copied().collect();

    let challenged_sectors =
        election::generate_sector_challenges(randomness_safe, challenge_count, &sectors)?;

    // Match the replicas to the challenges, as these are the only ones required.
    let challenged_replicas: Vec<_> = challenged_sectors
        .iter()
        .map(|c| {
            if let Some(replica) = replicas.get(c) {
                Ok((c, replica))
            } else {
                Err(anyhow!(
                    "Invalid challenge generated: {}, only {} sectors are being proven",
                    c,
                    sector_count
                ))
            }
        })
        .collect::<Result<_, _>>()?;

    // Generate merkle trees for the challenged replicas.
    // Merkle trees should be generated only once, not multiple times if the same sector is challenged
    // multiple times, so we build a HashMap of trees.

    let mut unique_challenged_replicas = challenged_replicas.clone();
    unique_challenged_replicas.sort_unstable(); // dedup requires a sorted list
    unique_challenged_replicas.dedup();

    let tree_size =
        get_tree_size::<<DefaultTreeHasher as Hasher>::Domain>(post_config.sector_size, OCT_ARITY)?;
    let tree_leafs = get_merkle_tree_leafs(tree_size, OCT_ARITY);

    let unique_trees_res: Vec<_> = unique_challenged_replicas
        .into_par_iter()
        .map(|(id, replica)| {
            replica
                .merkle_tree(tree_size, tree_leafs)
                .map(|tree| (*id, tree))
        })
        .collect();

    // resolve results
    let trees: BTreeMap<SectorId, LCTree> =
        unique_trees_res.into_iter().collect::<Result<_, _>>()?;

    let candidates = election::generate_candidates::<DefaultTreeHasher>(
        &public_params.vanilla_params,
        &challenged_sectors,
        &trees,
        prover_id_safe,
        randomness_safe,
    )?;

    info!("generate_candidates:finish");

    Ok(candidates)
}

pub type SnarkProof = Vec<u8>;

/// Generates a ticket from a partial_ticket.
pub fn finalize_ticket(partial_ticket: &[u8; 32]) -> Result<[u8; 32]> {
    let partial_ticket =
        bytes_into_fr::<Bls12>(partial_ticket).context("Invalid partial_ticket")?;
    Ok(election::finalize_ticket(&partial_ticket))
}

/// Generates a Election proof-of-spacetime.
///
/// # Arguments
///
/// * `post_config` - post config that contains the sector size of each sector that we are
/// generating this post for.
/// * `randomness` - randomness used to generate sector challenges.
/// * `replicas` - each sector's sector-id and associated replica info.
/// * `winners` - a vector containing each winning ticket.
/// * `prover_id` - the prover-id that is generating this post.
pub fn generate_election_post(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    winners: Vec<Candidate>,
    prover_id: ProverId,
) -> Result<Vec<SnarkProof>> {
    info!("generate_election_post:start");
    ensure!(
        post_config.typ == PoStType::Election,
        "invalid post config type"
    );

    let sector_count = replicas.len() as u64;
    ensure!(sector_count > 0, "Must supply at least one replica");
    ensure!(!winners.is_empty(), "Winners must not be empty");
    ensure!(!replicas.is_empty(), "Replicas must not be empty");

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "randomness")?;

    let vanilla_params = election_post_setup_params(&post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<election::ElectionPoSt<DefaultTreeHasher>> =
        ElectionPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params(&post_config)?;

    let tree_size =
        get_tree_size::<<DefaultTreeHasher as Hasher>::Domain>(post_config.sector_size, OCT_ARITY)?;
    let tree_leafs = get_merkle_tree_leafs(tree_size, OCT_ARITY);

    let mut proofs = Vec::with_capacity(winners.len());

    let inputs: Vec<_> = winners
        .par_iter()
        .map(|winner| {
            let replica = replicas
                .get(&winner.sector_id)
                .with_context(|| format!("Missing replica for sector: {}", winner.sector_id))?;
            let tree = replica.merkle_tree(tree_size, tree_leafs)?;

            let comm_r = replica.safe_comm_r()?;
            let pub_inputs = election::PublicInputs {
                randomness: randomness_safe,
                comm_r,
                sector_id: winner.sector_id,
                partial_ticket: winner.partial_ticket,
                sector_challenge_index: winner.sector_challenge_index,
                prover_id: prover_id_safe,
            };

            let comm_c = replica.safe_comm_c()?;
            let comm_r_last = replica.safe_comm_r_last()?;
            let priv_inputs = election::PrivateInputs::<DefaultTreeHasher> {
                tree,
                comm_c,
                comm_r_last,
            };

            Ok((pub_inputs, priv_inputs))
        })
        .collect::<Result<_>>()?;

    for (pub_inputs, priv_inputs) in &inputs {
        let proof =
            ElectionPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)?;
        proofs.push(proof.to_vec()?);
    }

    info!("generate_election_post:finish");

    Ok(proofs)
}

/// Verifies a election proof-of-spacetime.
///
/// # Arguments
///
/// * `post_config` - post config that contains the sector size of each sector that this post was
/// generated for.
/// * `randomness` - the randomness used to generate the sector challenges.
/// * `challenge_count` - the number of sector challenges in this post.
/// * `proofs` - each winning ticket's serialized circuit proof.
/// * `replicas` - each sector's sector-id and associated replica info.
/// * `winners` - a vector containing each winning ticket.
/// * `prover_id` - the prover-id that generated this post.
pub fn verify_election_post(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    challenge_count: u64,
    proofs: &[SnarkProof],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    winners: &[Candidate],
    prover_id: ProverId,
) -> Result<bool> {
    info!("verify_election_post:start");
    ensure!(
        post_config.typ == PoStType::Election,
        "invalid post config type"
    );

    let mut challenge_indexes: HashSet<_> = HashSet::new();

    // Fail early if any sector_challenge_index is duplicated.
    for winner in winners.iter() {
        if challenge_indexes.contains(&winner.sector_challenge_index) {
            return Err(anyhow!(
                "Invalid PoSt claiming duplicate sector_challenge_index: {}",
                &winner.sector_challenge_index
            ));
        } else {
            challenge_indexes.insert(&winner.sector_challenge_index);
        };
    }

    let sector_count = replicas.len() as u64;
    ensure!(sector_count > 0, "Must supply at least one replica");
    ensure!(!winners.is_empty(), "Winners must not be empty");
    ensure!(!proofs.is_empty(), "Proofs must not be empty");
    ensure!(!replicas.is_empty(), "Replicas must not be empty");
    ensure!(
        winners.len() == proofs.len(),
        "Mismatch between winners and proofs"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "randomness")?;

    let sectors = replicas.keys().copied().collect();
    let vanilla_params = election_post_setup_params(&post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<election::ElectionPoSt<DefaultTreeHasher>> =
        ElectionPoStCompound::setup(&setup_params)?;

    let verifying_key = get_post_verifying_key(&post_config)?;

    for (proof, winner) in proofs.iter().zip(winners.iter()) {
        let replica = replicas
            .get(&winner.sector_id)
            .with_context(|| format!("Missing replica for sector: {}", winner.sector_id))?;
        let comm_r = replica.safe_comm_r()?;

        if !election::is_valid_sector_challenge_index(
            challenge_count,
            winner.sector_challenge_index,
        ) {
            return Ok(false);
        }

        let expected_sector_id = election::generate_sector_challenge(
            randomness_safe,
            winner.sector_challenge_index as usize,
            &sectors,
        )?;
        if expected_sector_id != winner.sector_id {
            return Ok(false);
        }

        let proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key)?;
        let pub_inputs = election::PublicInputs {
            randomness: randomness_safe,
            comm_r,
            sector_id: winner.sector_id,
            partial_ticket: winner.partial_ticket,
            sector_challenge_index: winner.sector_challenge_index,
            prover_id: prover_id_safe,
        };

        let is_valid =
            ElectionPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)?;
        if !is_valid {
            return Ok(false);
        }
    }

    info!("verify_election_post:finish");

    Ok(true)
}

/// Generates a Winning proof-of-spacetime.
pub fn generate_winning_post(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    winner_id: SectorId,
    replica: PrivateReplicaInfo,
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_winning_post:start");
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "randomness")?;

    let vanilla_params = winning_post_setup_params(&post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<DefaultTreeHasher>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params(&post_config)?;

    let tree_size =
        get_tree_size::<<DefaultTreeHasher as Hasher>::Domain>(post_config.sector_size, OCT_ARITY)?;
    let tree_leafs = get_merkle_tree_leafs(tree_size, OCT_ARITY);

    let tree = replica.merkle_tree(tree_size, tree_leafs)?;
    let comm_r = replica.safe_comm_r()?;
    let comm_c = replica.safe_comm_c()?;
    let comm_r_last = replica.safe_comm_r_last()?;

    let pub_sectors: Vec<_> = (0..post_config.sector_count)
        .map(|_| fallback::PublicSector {
            id: winner_id,
            comm_r,
        })
        .collect();

    let priv_sectors: Vec<_> = (0..post_config.sector_count)
        .map(|_| fallback::PrivateSector {
            tree: &tree,
            comm_c,
            comm_r_last,
        })
        .collect();

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
    };

    let priv_inputs = fallback::PrivateInputs::<DefaultTreeHasher> {
        sectors: &priv_sectors,
    };

    let proof = fallback::FallbackPoStCompound::prove(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
    )?;
    let proof = proof.to_vec()?;

    info!("generate_winning_post:finish");

    Ok(proof)
}

/// Given some randomness and a list of sectors, generates the challenged sector.
pub fn generate_winning_post_sector_challenge(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    sector_set: &OrderedSectorSet,
) -> Result<SectorId> {
    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let randomness_safe =
        as_safe_commitment::<<DefaultTreeHasher as Hasher>::Domain, _>(randomness, "randomness")?;
    fallback::generate_sector_challenge(randomness_safe, sector_set)
}

/// Verifies a winning proof-of-spacetime.
pub fn verify_winning_post(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    winner_id: SectorId,
    replica: PublicReplicaInfo,
    prover_id: ProverId,
    sector_set: &OrderedSectorSet,
    proof: &[u8],
) -> Result<bool> {
    info!("verify_winning_post:start");

    ensure!(
        post_config.typ == PoStType::Winning,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "randomness")?;

    let vanilla_params = winning_post_setup_params(&post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<DefaultTreeHasher>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;

    let verifying_key = get_post_verifying_key(&post_config)?;

    let comm_r = replica.safe_comm_r()?;

    let expected_sector_id = fallback::generate_sector_challenge(randomness_safe, sector_set)?;
    if expected_sector_id != winner_id {
        return Ok(false);
    }

    let proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key)?;
    if proof.len() != 1 {
        return Ok(false);
    }

    let pub_sectors: Vec<_> = (0..post_config.sector_count)
        .map(|_| fallback::PublicSector {
            id: winner_id,
            comm_r,
        })
        .collect();

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
    };

    let is_valid =
        fallback::FallbackPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)?;

    if !is_valid {
        return Ok(false);
    }

    info!("verify_winning_post:finish");

    Ok(true)
}

/// Generates a Window proof-of-spacetime.
pub fn generate_window_post(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<SnarkProof> {
    info!("generate_window_post:start");
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "randomness")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: post_config.priority,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<DefaultTreeHasher>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params(&post_config)?;

    let tree_size =
        get_tree_size::<<DefaultTreeHasher as Hasher>::Domain>(post_config.sector_size, OCT_ARITY)?;
    let tree_leafs = get_merkle_tree_leafs(tree_size, OCT_ARITY);

    let trees: Vec<_> = replicas
        .iter()
        .map(|(_id, replica)| replica.merkle_tree(tree_size, tree_leafs))
        .collect::<Result<_>>()?;

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r = replica.safe_comm_r()?;
            Ok(fallback::PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let priv_sectors: Vec<_> = replicas
        .iter()
        .zip(trees.iter())
        .map(|((_sector_id, replica), tree)| {
            let comm_c = replica.safe_comm_c()?;
            let comm_r_last = replica.safe_comm_r_last()?;

            Ok(fallback::PrivateSector {
                tree,
                comm_c,
                comm_r_last,
            })
        })
        .collect::<Result<_>>()?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
    };

    let priv_inputs = fallback::PrivateInputs::<DefaultTreeHasher> {
        sectors: &priv_sectors,
    };

    let proof = fallback::FallbackPoStCompound::prove(
        &pub_params,
        &pub_inputs,
        &priv_inputs,
        &groth_params,
    )?;

    info!("generate_window_post:finish");

    Ok(proof.to_vec()?)
}

/// Verifies a window proof-of-spacetime.
pub fn verify_window_post(
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
    let prover_id_safe = as_safe_commitment(&prover_id, "randomness")?;

    let vanilla_params = window_post_setup_params(&post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
        priority: false,
    };
    let pub_params: compound_proof::PublicParams<fallback::FallbackPoSt<DefaultTreeHasher>> =
        fallback::FallbackPoStCompound::setup(&setup_params)?;

    let verifying_key = get_post_verifying_key(&post_config)?;

    let proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key)?;
    if proof.len() != 1 {
        return Ok(false);
    }

    let pub_sectors: Vec<_> = replicas
        .iter()
        .map(|(sector_id, replica)| {
            let comm_r = replica.safe_comm_r()?;
            Ok(fallback::PublicSector {
                id: *sector_id,
                comm_r,
            })
        })
        .collect::<Result<_>>()?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: &pub_sectors,
    };

    let is_valid =
        fallback::FallbackPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)?;

    if !is_valid {
        return Ok(false);
    }

    info!("verify_window_post:finish");

    Ok(true)
}
