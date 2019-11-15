use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use byteorder::{ByteOrder, LittleEndian};
use serde::de::Deserialize;
use serde::ser::Serialize;
use sha2::{Digest, Sha256};

use crate::crypto::pedersen::Hasher as PedersenHasher;
use crate::drgraph::graph_height;
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::proof::{NoRequirements, ProofScheme};
use crate::sector::*;
use crate::stacked::hash::hash2;
use crate::util::NODE_SIZE;

pub const POST_CHALLENGE_COUNT: usize = 8;
pub const POST_CHALLENGED_NODES: usize = 128;

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!(
            "ElectionPoSt::PublicParams{{sector_size: {}}}",
            self.sector_size(),
        )
    }

    fn sector_size(&self) -> u64 {
        self.sector_size
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub randomness: [u8; 32],
    pub sector_id: SectorId,
    pub prover_id: [u8; 32],
    pub comm_r: T,
    pub partial_ticket: [u8; 32],
    pub sector_challenge_index: u64,
}

#[derive(Debug, Clone)]
pub struct PrivateInputs<H: Hasher> {
    pub tree: MerkleTree<H::Domain, H::Function>,
    pub comm_c: H::Domain,
    pub comm_r_last: H::Domain,
}

/// The candidate data, that is needed for ticket generation.
#[derive(Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub sector_id: SectorId,
    pub partial_ticket: [u8; 32],
    pub ticket: [u8; 32],
    pub sector_challenge_index: u64,

    /// The data, in the order of the provided challenges.
    pub data: Vec<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Winner {
    pub sector_id: SectorId,
    pub partial_ticket: [u8; 32],
    pub ticket: [u8; 32],
    pub sector_challenge_index: u64,
}

impl fmt::Debug for Winner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Winner")
            .field("sector_id", &self.sector_id)
            .field("partial_ticket", &hex::encode(&self.partial_ticket))
            .field("ticket", &hex::encode(&self.ticket))
            .field("sector_challenge_index", &self.sector_challenge_index)
            .finish()
    }
}

impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("sector_id", &self.sector_id)
            .field("partial_ticket", &hex::encode(&self.partial_ticket))
            .field("ticket", &hex::encode(&self.ticket))
            .field("sector_challenge_index", &self.sector_challenge_index)
            .field(
                "data",
                &format!(
                    "{:?}",
                    self.data
                        .iter()
                        .map(|v| hex::encode(&v[..]))
                        .collect::<Vec<_>>()
                ),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    inclusion_proofs: Vec<MerkleProof<H>>,
    pub ticket: [u8; 32],
    pub comm_c: H::Domain,
}

impl<H: Hasher> Proof<H> {
    pub fn leafs(&self) -> Vec<&H::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::leaf)
            .collect()
    }

    pub fn commitments(&self) -> Vec<&H::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::root)
            .collect()
    }

    pub fn paths(&self) -> Vec<&Vec<(H::Domain, bool)>> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::path)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ElectionPoSt<'a, H>
where
    H: 'a + Hasher,
{
    _h: PhantomData<&'a H>,
}

pub fn generate_candidates<H: Hasher>(
    pub_params: &PublicParams,
    challenged_sectors: &[SectorId],
    trees: &BTreeMap<SectorId, &MerkleTree<H::Domain, H::Function>>,
    prover_id: &[u8; 32],
    randomness: &[u8; 32],
) -> Result<Vec<Candidate>> {
    let mut candidates = Vec::with_capacity(challenged_sectors.len());

    for (sector_challenge_index, sector_id) in challenged_sectors.iter().enumerate() {
        let tree = match trees.get(sector_id) {
            Some(tree) => tree,
            None => {
                return Err(
                    format_err!("Missing tree (private input) for sector {}", sector_id,).into(),
                )
            }
        };

        candidates.push(generate_candidate::<H>(
            pub_params,
            tree,
            prover_id,
            *sector_id,
            randomness,
            sector_challenge_index as u64,
        )?);
    }

    Ok(candidates)
}

fn generate_candidate<H: Hasher>(
    pub_params: &PublicParams,
    tree: &MerkleTree<H::Domain, H::Function>,
    prover_id: &[u8; 32],
    sector_id: SectorId,
    randomness: &[u8; 32],
    sector_challenge_index: u64,
) -> Result<Candidate> {
    // 1. read the data for each challenge
    let mut data = Vec::with_capacity(POST_CHALLENGE_COUNT);
    for n in 0..POST_CHALLENGE_COUNT {
        let challenge_start = generate_leaf_challenge(
            randomness,
            sector_challenge_index,
            n as u64,
            pub_params.sector_size,
        );

        let mut challenge_data = vec![0u8; POST_CHALLENGED_NODES * NODE_SIZE];
        let start = challenge_start as usize;
        let end = start + POST_CHALLENGED_NODES;

        tree.read_range_into(start, end, &mut challenge_data);

        data.push(challenge_data);
    }

    // 2. Ticket generation

    // partial_ticket = pedersen(randomness | data | prover_id | sector_id)

    let mut hasher = PedersenHasher::new(&randomness[..]);
    for chunk in &data {
        hasher.update(&chunk[..]);
    }
    hasher.update(&prover_id[..]);
    hasher.update(&u64::from(sector_id).to_le_bytes()[..]);

    let partial_ticket_hash = hasher.finalize_bytes();
    let mut partial_ticket = [0u8; 32];
    partial_ticket.copy_from_slice(&partial_ticket_hash);

    // ticket = sha256(partial_ticket)
    let ticket = finalize_ticket(&partial_ticket);

    Ok(Candidate {
        sector_challenge_index,
        sector_id,
        partial_ticket,
        ticket,
        data,
    })
}

pub fn finalize_ticket(partial_ticket: &[u8; 32]) -> [u8; 32] {
    let ticket_hash = Sha256::digest(&partial_ticket[..]);
    let mut ticket = [0u8; 32];
    ticket.copy_from_slice(&ticket_hash[..]);
    ticket
}

pub fn generate_sector_challenges(
    randomness: &[u8; 32],
    challenge_count: usize,
    sectors: &OrderedSectorSet,
) -> Result<Vec<SectorId>> {
    let mut challenges = Vec::with_capacity(challenge_count);

    for n in 0..challenge_count as usize {
        let sector = generate_sector_challenge(randomness, n, sectors)?;
        challenges.push(sector);
    }

    Ok(challenges)
}

pub fn generate_sector_challenge(
    randomness: &[u8; 32],
    n: usize,
    sectors: &OrderedSectorSet,
) -> Result<SectorId> {
    let mut hasher = Sha256::new();
    hasher.input(&randomness[..]);
    hasher.input(&n.to_le_bytes()[..]);
    let hash = hasher.result();

    let sector_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);
    let sector_index = (sector_challenge % sectors.len() as u64) as usize;
    let sector = *sectors
        .iter()
        .nth(sector_index)
        .expect("invalid challenge generated");

    Ok(sector)
}

/// Generate all challenged leaf ranges for a single sector, such that the range fits into the sector.
pub fn generate_leaf_challenges(
    randomness: &[u8; 32],
    sector_challenge_index: u64,
    sector_size: u64,
) -> Vec<u64> {
    let mut challenges = Vec::with_capacity(POST_CHALLENGE_COUNT);

    for leaf_challenge_index in 0..POST_CHALLENGE_COUNT {
        let challenge = generate_leaf_challenge(
            randomness,
            sector_challenge_index,
            leaf_challenge_index as u64,
            sector_size,
        );
        challenges.push(challenge)
    }

    challenges
}

/// Generates challenge, such that the range fits into the sector.
pub fn generate_leaf_challenge(
    randomness: &[u8; 32],
    sector_challenge_index: u64,
    leaf_challenge_index: u64,
    sector_size: u64,
) -> u64 {
    assert!(
        sector_size > POST_CHALLENGED_NODES as u64 * NODE_SIZE as u64,
        "sector size {} is too small",
        sector_size
    );

    let mut hasher = Sha256::new();
    hasher.input(&randomness[..]);
    hasher.input(&sector_challenge_index.to_le_bytes()[..]);
    hasher.input(&leaf_challenge_index.to_le_bytes()[..]);
    let hash = hasher.result();

    let leaf_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);

    let sector_part = leaf_challenge % (sector_size / (POST_CHALLENGED_NODES * NODE_SIZE) as u64);

    sector_part * POST_CHALLENGED_NODES as u64
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for ElectionPoSt<'a, H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<H>;
    type Proof = Proof<H>;
    type Requirements = NoRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            sector_size: sp.sector_size,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        // 1. Inclusions proofs of all challenged leafs in all challenged ranges
        let tree = &priv_inputs.tree;
        let sector_size = pub_params.sector_size;

        let inclusion_proofs = (0..POST_CHALLENGE_COUNT)
            .flat_map(|n| {
                let challenged_leaf_start = generate_leaf_challenge(
                    &pub_inputs.randomness,
                    pub_inputs.sector_challenge_index,
                    n as u64,
                    sector_size,
                );
                (0..POST_CHALLENGED_NODES).map(move |i| {
                    MerkleProof::new_from_proof(&tree.gen_proof(challenged_leaf_start as usize + i))
                })
            })
            .collect::<Vec<_>>();

        // 2. correct generation of the ticket from the partial_ticket (add this to the candidate)
        let ticket = finalize_ticket(&pub_inputs.partial_ticket);

        Ok(Proof {
            inclusion_proofs,
            ticket,
            comm_c: priv_inputs.comm_c,
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let sector_size = pub_params.sector_size;

        // verify that H(Comm_c || Comm_r_last) == Comm_R
        // comm_r_last is the root of the proof
        let comm_r_last = proof.inclusion_proofs[0].root();
        let comm_c = proof.comm_c;
        let comm_r = &pub_inputs.comm_r;

        if AsRef::<[u8]>::as_ref(&hash2(comm_c, comm_r_last)) != AsRef::<[u8]>::as_ref(comm_r) {
            return Ok(false);
        }

        for n in 0..POST_CHALLENGE_COUNT {
            let challenged_leaf_start = generate_leaf_challenge(
                &pub_inputs.randomness,
                pub_inputs.sector_challenge_index,
                n as u64,
                sector_size,
            );
            for i in 0..POST_CHALLENGED_NODES {
                let merkle_proof = &proof.inclusion_proofs[n * POST_CHALLENGED_NODES + i];

                // validate all comm_r_lasts match
                if merkle_proof.root() != comm_r_last {
                    return Ok(false);
                }

                // validate the path length
                if graph_height(pub_params.sector_size as usize / NODE_SIZE)
                    != merkle_proof.path().len()
                {
                    return Ok(false);
                }

                if !merkle_proof.validate(challenged_leaf_start as usize) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}
