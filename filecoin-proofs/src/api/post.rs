use std::collections::BTreeMap;
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
pub struct PrivateReplicaInfo {
    /// Path to the replica.
    access: String,
    /// The replica commitment.
    commitment: Commitment,
    /// Is this sector marked as a fault?
    is_fault: bool,
}

impl std::cmp::Ord for PrivateReplicaInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.commitment.as_ref().cmp(other.commitment.as_ref())
    }
}

impl std::cmp::PartialOrd for PrivateReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PrivateReplicaInfo {
    pub fn new(access: String, commitment: Commitment) -> Self {
        PrivateReplicaInfo {
            access,
            commitment,
            is_fault: false,
        }
    }

    pub fn new_faulty(access: String, commitment: Commitment) -> Self {
        PrivateReplicaInfo {
            access,
            commitment,
            is_fault: true,
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

/// The minimal information required about a replica, in order to be able to verify
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicReplicaInfo {
    /// The replica commitment.
    commitment: Commitment,
    /// Is this sector marked as a fault?
    is_fault: bool,
}

impl std::cmp::Ord for PublicReplicaInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.commitment.as_ref().cmp(other.commitment.as_ref())
    }
}

impl std::cmp::PartialOrd for PublicReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PublicReplicaInfo {
    pub fn new(commitment: Commitment) -> Self {
        PublicReplicaInfo {
            commitment,
            is_fault: false,
        }
    }

    pub fn new_faulty(commitment: Commitment) -> Self {
        PublicReplicaInfo {
            commitment,
            is_fault: true,
        }
    }

    pub fn safe_commitment(&self) -> Result<PedersenDomain, failure::Error> {
        as_safe_commitment(&self.commitment, "comm_r")
    }
}

/// Generates a proof-of-spacetime.
/// Accepts as input a challenge seed, configuration struct, and a vector of
/// sealed sector file-path plus CommR tuples, as well as a list of faults.
pub fn generate_post(
    post_config: PoStConfig,
    challenge_seed: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo>,
) -> error::Result<Vec<u8>> {
    let sector_count = replicas.len() as u64;
    let sector_size = u64::from(PaddedBytesAmount::from(post_config));

    let vanilla_params = post_setup_params(post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params: &vanilla_params,
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };

    let pub_params: compound_proof::PublicParams<_, rational_post::RationalPoSt<PedersenHasher>> =
        RationalPoStCompound::setup(&setup_params)?;

    let sectors = replicas.keys().copied().collect();
    let faults = replicas
        .iter()
        .filter_map(
            |(id, replica)| {
                if replica.is_fault {
                    Some(*id)
                } else {
                    None
                }
            },
        )
        .collect();

    let challenges = rational_post::derive_challenges(
        vanilla_params.challenges_count,
        sector_size,
        &sectors,
        challenge_seed,
        &faults,
    )?;

    // Match the replicas to the challenges, as these are the only ones required.
    let challenged_replicas: Vec<_> = challenges
        .iter()
        .map(|c| {
            if let Some(replica) = replicas.get(&c.sector) {
                Ok((c.sector, replica))
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
        .map(|(id, replica)| replica.merkle_tree(sector_size).map(|tree| (id, tree)))
        .collect();

    // resolve results
    let unique_trees: BTreeMap<SectorId, Tree> =
        unique_trees_res.into_iter().collect::<Result<_, _>>()?;

    let borrowed_trees: BTreeMap<SectorId, &Tree> = challenged_replicas
        .iter()
        .map(|(id, _)| {
            if let Some(tree) = unique_trees.get(id) {
                Ok((*id, tree))
            } else {
                Err(format_err!(
                    "Bug: Failed to generate merkle tree for {} sector",
                    id
                ))
            }
        })
        .collect::<Result<_, _>>()?;

    // Construct the list of actual commitments
    let commitments: Vec<_> = challenged_replicas
        .iter()
        .map(|(_id, replica)| replica.safe_commitment())
        .collect::<Result<_, _>>()?;

    let pub_inputs = rational_post::PublicInputs {
        challenges: &challenges,
        commitments: &commitments,
        faults: &faults,
    };

    let priv_inputs = rational_post::PrivateInputs::<PedersenHasher> {
        trees: &borrowed_trees,
    };

    let groth_params = get_post_params(post_config)?;

    let proof = RationalPoStCompound::prove(&pub_params, &pub_inputs, &priv_inputs, &groth_params)?;

    Ok(proof.to_vec())
}

/// Verifies a proof-of-spacetime.
pub fn verify_post(
    post_config: PoStConfig,
    challenge_seed: &ChallengeSeed,
    proof: &[u8],
    replicas: &BTreeMap<SectorId, PublicReplicaInfo>,
) -> error::Result<bool> {
    let sector_size = u64::from(PaddedBytesAmount::from(post_config));
    let sector_count = replicas.len() as u64;

    let vanilla_params = post_setup_params(post_config);
    let setup_params = compound_proof::SetupParams {
        vanilla_params: &vanilla_params,
        engine_params: &(*ENGINE_PARAMS),
        partitions: None,
    };

    let sectors = replicas.keys().copied().collect();
    let faults = replicas
        .iter()
        .filter_map(
            |(id, replica)| {
                if replica.is_fault {
                    Some(*id)
                } else {
                    None
                }
            },
        )
        .collect();

    let challenges = rational_post::derive_challenges(
        vanilla_params.challenges_count,
        sector_size,
        &sectors,
        challenge_seed,
        &faults,
    )?;

    // Match the replicas to the challenges, as these are the only ones required.
    let commitments: Vec<_> = challenges
        .iter()
        .map(|c| {
            if let Some(replica) = replicas.get(&c.sector) {
                replica.safe_commitment()
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
