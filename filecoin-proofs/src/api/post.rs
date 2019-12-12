use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

use anyhow::{anyhow, ensure, Context, Result};
use bincode::deserialize;
use log::info;
use merkletree::merkle::{get_merkle_tree_leafs, MerkleTree};
use merkletree::store::{DiskStore, Store, StoreConfig, DEFAULT_CACHED_ABOVE_BASE_LAYER};
use paired::bls12_381::Bls12;
use rayon::prelude::*;
use storage_proofs::circuit::election_post::ElectionPoStCompound;
use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgraph::DefaultTreeHasher;
use storage_proofs::election_post;
use storage_proofs::fr32::bytes_into_fr;
use storage_proofs::hasher::Hasher;
use storage_proofs::proof::NoRequirements;
use storage_proofs::sector::*;
use storage_proofs::stacked::CacheKey;

use crate::api::util::as_safe_commitment;
use crate::caches::{get_post_params, get_post_verifying_key};
use crate::parameters::post_setup_params;
use crate::types::{
    ChallengeSeed, Commitment, PersistentAux, PoStConfig, ProverId, SectorSize, Tree,
};

pub use storage_proofs::election_post::Candidate;

/// The minimal information required about a replica, in order to be able to generate
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivateReplicaInfo {
    /// Path to the replica.
    access: String,
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
    pub fn new(access: String, comm_r: Commitment, cache_dir: PathBuf) -> Result<Self> {
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

        Ok(PrivateReplicaInfo {
            access,
            comm_r,
            aux,
            cache_dir,
        })
    }

    pub fn safe_comm_r(&self) -> Result<<DefaultTreeHasher as Hasher>::Domain> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }

    pub fn safe_comm_c(&self) -> Result<<DefaultTreeHasher as Hasher>::Domain> {
        Ok(self.aux.comm_c)
    }

    pub fn safe_comm_q(&self) -> Result<<DefaultTreeHasher as Hasher>::Domain> {
        Ok(self.aux.comm_q)
    }

    pub fn safe_comm_r_last(&self) -> Result<<DefaultTreeHasher as Hasher>::Domain> {
        Ok(self.aux.comm_r_last)
    }

    /// Generate the merkle tree of this particular replica.
    pub fn merkle_tree(&self, tree_size: usize, tree_leafs: usize) -> Result<Tree> {
        let mut config = StoreConfig::new(
            &self.cache_dir,
            CacheKey::CommRLastTree.to_string(),
            DEFAULT_CACHED_ABOVE_BASE_LAYER,
        );
        config.size = Some(tree_size);
        let tree_r_last_store: DiskStore<<DefaultTreeHasher as Hasher>::Domain> =
            DiskStore::new_from_disk(tree_size, &config)?;
        let tree_r_last: Tree = MerkleTree::from_data_store(tree_r_last_store, tree_leafs)?;

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

fn get_tree_size(sector_size: SectorSize) -> usize {
    let sector_size = u64::from(sector_size);
    let elems = sector_size as usize / std::mem::size_of::<<DefaultTreeHasher as Hasher>::Domain>();

    2 * elems - 1
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
    post_config: PoStConfig,
    randomness: &ChallengeSeed,
    challenge_count: u64,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<Vec<Candidate>> {
    info!("generate_candidates:start");

    let vanilla_params = post_setup_params(post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
    };
    let public_params: compound_proof::PublicParams<
        election_post::ElectionPoSt<DefaultTreeHasher>,
    > = ElectionPoStCompound::setup(&setup_params)?;

    let sector_count = replicas.len() as u64;
    ensure!(sector_count > 0, "Must supply at least one replica");

    let sectors = replicas.keys().copied().collect();

    let challenged_sectors =
        election_post::generate_sector_challenges(randomness, challenge_count, &sectors)?;

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

    let tree_size = get_tree_size(post_config.sector_size);
    let tree_leafs = get_merkle_tree_leafs(tree_size);

    let unique_trees_res: Vec<_> = unique_challenged_replicas
        .into_par_iter()
        .map(|(id, replica)| {
            replica
                .merkle_tree(tree_size, tree_leafs)
                .map(|tree| (*id, tree))
        })
        .collect();

    // resolve results
    let trees: BTreeMap<SectorId, Tree> = unique_trees_res.into_iter().collect::<Result<_, _>>()?;

    let candidates = election_post::generate_candidates::<DefaultTreeHasher>(
        public_params.vanilla_params.sector_size,
        &challenged_sectors,
        &trees,
        &prover_id,
        randomness,
    )?;

    info!("generate_candidates:finish");

    Ok(candidates)
}

pub type SnarkProof = Vec<u8>;

/// Generates a ticket from a partial_ticket.
pub fn finalize_ticket(partial_ticket: &[u8; 32]) -> Result<[u8; 32]> {
    let partial_ticket =
        bytes_into_fr::<Bls12>(partial_ticket).context("Invalid partial_ticket")?;
    Ok(election_post::finalize_ticket(&partial_ticket))
}

/// Generates a proof-of-spacetime.
///
/// # Arguments
///
/// * `post_config` - post config that contains the sector size of each sector that we are
/// generating this post for.
/// * `randomness` - randomness used to generate sector challenges.
/// * `replicas` - each sector's sector-id and associated replica info.
/// * `winners` - a vector containing each winning ticket.
/// * `prover_id` - the prover-id that is generating this post.
pub fn generate_post(
    post_config: PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
    winners: Vec<Candidate>,
    prover_id: ProverId,
) -> Result<Vec<SnarkProof>> {
    info!("generate_post:start");

    let sector_count = replicas.len() as u64;
    ensure!(sector_count > 0, "Must supply at least one replica");

    let vanilla_params = post_setup_params(post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
    };
    let pub_params: compound_proof::PublicParams<election_post::ElectionPoSt<DefaultTreeHasher>> =
        ElectionPoStCompound::setup(&setup_params)?;
    let groth_params = get_post_params(post_config)?;

    let tree_size = get_tree_size(post_config.sector_size);
    let tree_leafs = get_merkle_tree_leafs(tree_size);

    let mut proofs = Vec::with_capacity(winners.len());

    let inputs: Vec<_> = winners
        .par_iter()
        .map(|winner| {
            let replica = replicas
                .get(&winner.sector_id)
                .with_context(|| format!("Missing replica for sector: {}", winner.sector_id))?;
            let tree = replica.merkle_tree(tree_size, tree_leafs)?;

            let comm_r = replica.safe_comm_r()?;
            let pub_inputs = election_post::PublicInputs {
                randomness: *randomness,
                comm_r,
                sector_id: winner.sector_id,
                partial_ticket: winner.partial_ticket,
                sector_challenge_index: winner.sector_challenge_index,
                prover_id,
            };

            let comm_c = replica.safe_comm_c()?;
            let comm_q = replica.safe_comm_q()?;
            let comm_r_last = replica.safe_comm_r_last()?;
            let priv_inputs = election_post::PrivateInputs::<DefaultTreeHasher> {
                tree,
                comm_c,
                comm_q,
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

    info!("generate_post:finish");

    Ok(proofs)
}

/// Verifies a proof-of-spacetime.
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
pub fn verify_post(
    post_config: PoStConfig,
    randomness: &ChallengeSeed,
    challenge_count: u64,
    proofs: &[Vec<u8>],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
    winners: &[Candidate],
    prover_id: ProverId,
) -> Result<bool> {
    info!("verify_post:start");

    let sector_count = replicas.len() as u64;
    ensure!(sector_count > 0, "Must supply at least one replica");
    ensure!(
        winners.len() == proofs.len(),
        "Missmatch between winners and proofs"
    );

    let sectors = replicas.keys().copied().collect();
    let vanilla_params = post_setup_params(post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions: None,
    };
    let pub_params: compound_proof::PublicParams<election_post::ElectionPoSt<DefaultTreeHasher>> =
        ElectionPoStCompound::setup(&setup_params)?;

    let verifying_key = get_post_verifying_key(post_config)?;
    for (proof, winner) in proofs.iter().zip(winners.iter()) {
        let replica = replicas
            .get(&winner.sector_id)
            .with_context(|| format!("Missing replica for sector: {}", winner.sector_id))?;
        let comm_r = replica.safe_comm_r()?;

        if !election_post::is_valid_sector_challenge_index(
            challenge_count,
            winner.sector_challenge_index,
        ) {
            return Ok(false);
        }

        let expected_sector_id = election_post::generate_sector_challenge(
            randomness,
            winner.sector_challenge_index as usize,
            &sectors,
        )?;
        if expected_sector_id != winner.sector_id {
            return Ok(false);
        }

        let proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key)?;
        let pub_inputs = election_post::PublicInputs {
            randomness: *randomness,
            comm_r,
            sector_id: winner.sector_id,
            partial_ticket: winner.partial_ticket,
            sector_challenge_index: winner.sector_challenge_index,
            prover_id,
        };

        let is_valid =
            ElectionPoStCompound::verify(&pub_params, &pub_inputs, &proof, &NoRequirements)?;
        if !is_valid {
            return Ok(false);
        }
    }

    info!("verify_post:finish");

    Ok(true)
}
