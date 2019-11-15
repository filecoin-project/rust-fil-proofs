use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::marker::PhantomData;

use byteorder::{ByteOrder, LittleEndian};
use serde::de::Deserialize;
use serde::ser::Serialize;
use sha2::{Digest, Sha256};

use crate::crypto::pedersen::Hasher as PedersenHasher;
use crate::error::Result;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::proof::{NoRequirements, ProofScheme};
use crate::sector::*;
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
pub struct PublicInputs<'a, T: 'a + Domain> {
    /// The challenges, which leafs to prove.
    pub challenges: &'a [Challenge],
    pub faults: &'a OrderedSectorSet,
    pub comm_rs: &'a [T],
}

#[derive(Debug, Clone)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub trees: &'a BTreeMap<SectorId, &'a MerkleTree<H::Domain, H::Function>>,
    pub comm_cs: &'a [H::Domain],
    pub comm_r_lasts: &'a [H::Domain],
}

/// The witness data, that is needed for ticket generation.
#[derive(Clone, Serialize, Deserialize)]
pub struct Witness {
    pub ticket: [u8; 32],
    /// The data, in the order of the provided challenges.
    pub data: Vec<Vec<u8>>,
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Witness")
            .field("ticket", &hex::encode(&self.ticket))
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
    pub comm_cs: Vec<H::Domain>,
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

/// A challenge specifying a sector, and a leaf range.
/// The range is of size `POST_CHALLENGED_NODES`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    // The identifier of the challenged sector.
    pub sector: SectorId,
    // The leaf index this challenge starts at.
    pub start: u64,
}

#[derive(Debug, Clone)]
pub struct ElectionPoSt<'a, H>
where
    H: 'a + Hasher,
{
    _h: PhantomData<&'a H>,
}

impl<'a, H: 'a + Hasher> ElectionPoSt<'a, H> {
    pub fn generate_witness(
        pub_params: &PublicParams,
        challenged_sectors: &[SectorId],
        trees: &'a BTreeMap<SectorId, &'a MerkleTree<H::Domain, H::Function>>,
        prover_id: &[u8; 32],
        seed: &[u8; 32],
    ) -> Result<HashMap<SectorId, Witness>> {
        let mut res = HashMap::with_capacity(challenged_sectors.len());

        for sector_id in challenged_sectors {
            let tree = match trees.get(sector_id) {
                Some(tree) => tree,
                None => {
                    return Err(format_err!(
                        "Missing tree (private input) for sector {}",
                        sector_id,
                    )
                    .into())
                }
            };

            let witness =
                Self::generate_single_witness(pub_params, tree, prover_id, *sector_id, seed)?;
            res.insert(*sector_id, witness);
        }

        Ok(res)
    }

    fn generate_single_witness(
        pub_params: &PublicParams,
        tree: &'a MerkleTree<H::Domain, H::Function>,
        prover_id: &[u8; 32],
        sector_id: SectorId,
        seed: &[u8; 32],
    ) -> Result<Witness> {
        // 1. read the data for each challenge
        let mut data = Vec::with_capacity(POST_CHALLENGE_COUNT);
        for n in 0..POST_CHALLENGE_COUNT {
            let challenge_start = generate_challenge(seed, n as u64, pub_params.sector_size);

            let mut challenge_data = vec![0u8; POST_CHALLENGED_NODES * NODE_SIZE];
            let start = challenge_start as usize;
            let end = start + POST_CHALLENGED_NODES;

            tree.read_range_into(start, end, &mut challenge_data);

            data.push(challenge_data);
        }

        // 2. Ticket generation

        // partial_ticket = pedersen(seed | data | prover_id | sector_id)

        let mut hasher = PedersenHasher::new(&seed[..]);
        for chunk in &data {
            hasher.update(&chunk[..]);
        }
        hasher.update(&prover_id[..]);
        hasher.update(&u64::from(sector_id).to_le_bytes()[..]);

        let partial_ticket = hasher.finalize_bytes();

        // ticket = sha256(partial_ticket)
        let ticket_hash = Sha256::digest(&partial_ticket);
        let mut ticket = [0u8; 32];
        ticket.copy_from_slice(&ticket_hash[..]);

        Ok(Witness { ticket, data })
    }

    pub fn generate_sector_challenges(
        seed: &[u8; 32],
        challenge_count: usize,
        sectors: &OrderedSectorSet,
    ) -> Result<Vec<SectorId>> {
        let mut challenges = Vec::with_capacity(challenge_count);

        for n in 0..challenge_count as usize {
            let sector = Self::generate_sector_challenge(seed, n, sectors)?;
            challenges.push(sector);
        }

        Ok(challenges)
    }

    pub fn generate_sector_challenge(
        seed: &[u8; 32],
        n: usize,
        sectors: &OrderedSectorSet,
    ) -> Result<SectorId> {
        let mut hasher = Sha256::new();
        hasher.input(&seed[..]);
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
}

/// Generates challenge, such that the range fits into the sector.
fn generate_challenge(seed: &[u8; 32], n: u64, sector_size: u64) -> u64 {
    assert!(
        sector_size > POST_CHALLENGED_NODES as u64 * NODE_SIZE as u64,
        "sector size {} is too small",
        sector_size
    );

    let mut hasher = Sha256::new();
    hasher.input(&seed[..]);
    hasher.input(&n.to_le_bytes()[..]);
    let hash = hasher.result();

    let leaf_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);

    let sector_part = leaf_challenge % (sector_size / (POST_CHALLENGED_NODES * NODE_SIZE) as u64);

    let start = sector_part * POST_CHALLENGED_NODES as u64;

    start
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for ElectionPoSt<'a, H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;
    type Requirements = NoRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            sector_size: sp.sector_size,
        })
    }

    fn prove<'b>(
        _pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        unimplemented!();
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        unimplemented!();
    }
}
