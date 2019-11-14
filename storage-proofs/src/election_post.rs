use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::marker::PhantomData;

use byteorder::{ByteOrder, LittleEndian};
use serde::de::Deserialize;
use serde::ser::Serialize;
use sha2::{Digest, Sha256};

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
#[derive(Clone)]
pub struct Witness {
    pub ticket: [u8; 32],
    /// The data, in the order of the provided challenges.
    pub data: Vec<[u8; POST_CHALLENGED_NODES * NODE_SIZE]>,
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
        _pub_params: &PublicParams,
        pub_inputs: &PublicInputs<H::Domain>,
        priv_inputs: &PrivateInputs<H>,
        seed: &[u8; 32],
    ) -> Result<Witness> {
        // 1. read the data for each challenge
        let mut data = Vec::with_capacity(POST_CHALLENGE_COUNT);
        for challenge in pub_inputs.challenges {
            let tree = match priv_inputs.trees.get(&challenge.sector) {
                Some(tree) => tree,
                None => {
                    return Err(format_err!(
                        "Missing tree (private input) for sector {}",
                        challenge.sector
                    )
                    .into())
                }
            };

            let mut challenge_data = [0u8; POST_CHALLENGED_NODES * NODE_SIZE];
            let start = challenge.start as usize;
            let end = start + POST_CHALLENGED_NODES;

            tree.read_range_into(start, end, &mut challenge_data);

            data.push(challenge_data);
        }

        // 2. hash the leafs, together with the seed
        let mut hasher = Sha256::new();
        hasher.input(&seed);
        for chunk in &data {
            hasher.input(&chunk[..]);
        }

        let mut ticket = [0u8; 32];
        ticket.copy_from_slice(&hasher.result());

        Ok(Witness { ticket, data })
    }

    pub fn generate_challenges(
        pub_params: &PublicParams,
        seed: &[u8],
        sectors: &OrderedSectorSet,
        faults: &OrderedSectorSet,
    ) -> Result<Vec<Challenge>> {
        (0..POST_CHALLENGE_COUNT)
            .map(|n| {
                let mut attempt = 0;
                let mut attempted_sectors = HashSet::new();
                loop {
                    let c = generate_challenge(
                        seed,
                        n as u64,
                        attempt,
                        pub_params.sector_size,
                        sectors,
                    );

                    // check for faulty sector
                    if !faults.contains(&c.sector) {
                        // valid challenge, not found
                        return Ok(c);
                    } else {
                        attempt += 1;
                        attempted_sectors.insert(c.sector);

                        ensure!(
                            attempted_sectors.len() < sectors.len(),
                            "all sectors are faulty"
                        );
                    }
                }
            })
            .collect::<std::result::Result<_, failure::Error>>()
            .map_err(Into::into)
    }
}

/// Generates challenge, such that the range fits into the sector.
fn generate_challenge(
    seed: &[u8],
    n: u64,
    attempt: u64,
    sector_size: u64,
    sectors: &OrderedSectorSet,
) -> Challenge {
    let mut data = seed.to_vec();
    data.extend_from_slice(&n.to_le_bytes()[..]);
    data.extend_from_slice(&attempt.to_le_bytes()[..]);

    let hash = Sha256::digest(&data);
    let sector_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);
    let leaf_challenge = LittleEndian::read_u64(&hash.as_ref()[8..16]);

    let sector_index = (sector_challenge % sectors.len() as u64) as usize;
    let sector = *sectors
        .iter()
        .nth(sector_index)
        .expect("invalid challenge generated");

    let sector_part = leaf_challenge % (sector_size / (POST_CHALLENGED_NODES * NODE_SIZE) as u64);
    let start = sector_part * NODE_SIZE as u64;

    Challenge { sector, start }
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
