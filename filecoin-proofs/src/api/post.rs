use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use rayon::prelude::*;
use storage_proofs::circuit::multi_proof::MultiProof;
use storage_proofs::circuit::rational_post::RationalPoStCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgraph::Graph;
use storage_proofs::error::Error;
use storage_proofs::hasher::pedersen::{PedersenDomain, PedersenHasher};
use storage_proofs::proof::NoRequirements;
use storage_proofs::rational_post;
use storage_proofs::sector::*;

use crate::api::{as_safe_commitment, ChallengeSeed, Commitment, Tree};
use crate::caches::{get_post_params, get_post_verifying_key};
use crate::error;
use crate::parameters::{post_setup_params, public_params};
use crate::singletons::ENGINE_PARAMS;
use crate::types::{PaddedBytesAmount, PoStConfig};

/// The minimal information required about a replica, in order to be able to generate
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReplicaInfo {
    /// The id of this sector.
    sector_id: SectorId,
    /// Path to the replica.
    access: String,
    /// The replica commitment.
    commitment: Commitment,
}

impl std::cmp::Ord for ReplicaInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.commitment.as_ref().cmp(other.commitment.as_ref())
    }
}

impl std::cmp::PartialOrd for ReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ReplicaInfo {
    pub fn new(id: SectorId, access: String, commitment: Commitment) -> Self {
        ReplicaInfo {
            sector_id: id,
            access,
            commitment,
        }
    }

    pub fn safe_commitment(&self) -> Result<PedersenDomain, failure::Error> {
        as_safe_commitment(&self.commitment, "comm_r")
    }

    /// Generate the merkle tree of this particular replica.
    pub fn merkle_tree(&self, sector_size: u64) -> Result<Tree, Error> {
        let mut f_in = File::open(&self.access)?;
        let mut data = Vec::new();
        f_in.read_to_end(&mut data)?;

        let bytes = PaddedBytesAmount(sector_size as u64);
        public_params(bytes, 1).graph.merkle_tree(&data)
    }
}

/// Generates a proof-of-spacetime.
/// Accepts as input a challenge seed, configuration struct, and a vector of
/// sealed sector file-path plus CommR tuples, as well as a list of faults.
pub fn generate_post(
    post_config: PoStConfig,
    challenge_seed: &ChallengeSeed,
    replicas: &[ReplicaInfo],
    sectors: &SectorSet,
    faults: &SectorSet,
) -> error::Result<Vec<u8>> {
    let sector_count = replicas.len() as u64;
    let sector_size = u64::from(PaddedBytesAmount::from(post_config));

    // Only one fault per sector is possible.
    ensure!(
        faults.len() as u64 <= sector_count,
        "Too many faults submitted"
    );

    let vanilla_params = post_setup_params(post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params: &vanilla_params,
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };

    let pub_params: compound_proof::PublicParams<_, rational_post::RationalPoSt<PedersenHasher>> =
        RationalPoStCompound::setup(&setup_params)?;

    let challenges = rational_post::derive_challenges(
        vanilla_params.challenges_count,
        sector_size,
        sectors,
        challenge_seed,
        faults,
    );

    // Match the replicas to the challenges, as these are the only ones required.
    let challenged_replicas: Vec<_> = challenges
        .iter()
        .map(|c| {
            if let Some(replica) = replicas.iter().find(|r| r.sector_id == c.sector) {
                Ok(replica)
            } else {
                Err(format_err!(
                    "Invalid challenge generated: {}, only {} sectors are being proven",
                    c.sector,
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

    let unique_trees_res: Vec<_> = unique_challenged_replicas
        .into_par_iter()
        .map(|replica| replica.merkle_tree(sector_size).map(|tree| (replica, tree)))
        .collect();

    // resolve results
    let unique_trees: HashMap<&ReplicaInfo, Tree> =
        unique_trees_res.into_iter().collect::<Result<_, _>>()?;

    let borrowed_trees: Vec<&Tree> = challenged_replicas
        .iter()
        .map(|replica| {
            // Safe to unwrap, as we constructed the HashMap such that each of these has an entry.
            unique_trees.get(*replica).unwrap()
        })
        .collect();

    // Construct the list of actual commitments
    let commitments: Vec<_> = challenged_replicas
        .iter()
        .map(|replica| replica.safe_commitment())
        .collect::<Result<_, _>>()?;

    let pub_inputs = rational_post::PublicInputs {
        challenges: &challenges,
        commitments: &commitments,
        faults,
    };

    let priv_inputs = rational_post::PrivateInputs::<PedersenHasher> {
        trees: &borrowed_trees[..],
    };

    let groth_params = get_post_params(post_config)?;

    let proof = RationalPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)?;

    Ok(proof.to_vec())
}

/// Verifies a proof-of-spacetime.
pub fn verify_post(
    post_config: PoStConfig,
    comm_rs: Vec<Commitment>,
    challenge_seed: &ChallengeSeed,
    proof: &[u8],
    sectors: &SectorSet,
    faults: &SectorSet,
) -> error::Result<bool> {
    let sector_size = u64::from(PaddedBytesAmount::from(post_config));
    let sector_count = comm_rs.len() as u64;

    // Only one fault per sector is possible.
    ensure!(faults.len() as u64 <= sector_count, "Too many faults");

    let vanilla_params = post_setup_params(post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params: &vanilla_params,
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };
    let commitments_all: Vec<PedersenDomain> = comm_rs
        .iter()
        .map(|c| as_safe_commitment(c, "comm_r"))
        .collect::<Result<_, _>>()?;

    let challenges = rational_post::derive_challenges(
        vanilla_params.challenges_count,
        sector_size,
        sectors,
        challenge_seed,
        faults,
    );

    // Match the replicas to the challenges, as these are the only ones required.
    let commitments: Vec<_> = challenges
        .iter()
        .map(|c| {
            if let Some(comm) = commitments_all.get(u64::from(c.sector) as usize) {
                Ok(*comm)
            } else {
                Err(format_err!(
                    "Invalid challenge generated: {}, only {} sectors are being proven",
                    c.sector,
                    sector_count
                ))
            }
        })
        .collect::<Result<_, _>>()?;

    let public_params: compound_proof::PublicParams<
        _,
        rational_post::RationalPoSt<PedersenHasher>,
    > = RationalPoStCompound::setup(&setup_params)?;

    let public_inputs = rational_post::PublicInputs::<PedersenDomain> {
        challenges: &challenges,
        commitments: &commitments,
        faults: &faults,
    };

    let verifying_key = get_post_verifying_key(post_config)?;

    let proof = MultiProof::new_from_reader(None, &proof[..], &verifying_key)?;

    let is_valid =
        RationalPoStCompound::verify(&public_params, &public_inputs, &proof, &NoRequirements)?;

    // Since callers may rely on previous mocked success, just pretend verification succeeded, for now.
    Ok(is_valid)
}
