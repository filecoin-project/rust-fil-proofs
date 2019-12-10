use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use anyhow::{bail, ensure, Context};
use byteorder::{ByteOrder, LittleEndian};
use paired::bls12_381::{Bls12, Fr};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::pedersen::{pedersen_md_no_padding_bits, Bits};
use crate::drgraph::graph_height;
use crate::error::{Error, Result};
use crate::fr32::fr_into_bytes;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::proof::{NoRequirements, ProofScheme};
use crate::sector::*;
use crate::stacked::hash::hash3;
use crate::util::NODE_SIZE;

pub const POST_CHALLENGE_COUNT: usize = 40;
pub const POST_CHALLENGED_NODES: usize = 1;

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
            "ElectionPoSt::PublicParams{{sector_size: {}, count: {}, nodes: {}}}",
            self.sector_size(),
            POST_CHALLENGE_COUNT,
            POST_CHALLENGED_NODES,
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
    pub partial_ticket: Fr,
    pub sector_challenge_index: u64,
}

#[derive(Debug, Clone)]
pub struct PrivateInputs<H: Hasher> {
    pub tree: MerkleTree<H::Domain, H::Function>,
    pub comm_c: H::Domain,
    pub comm_q: H::Domain,
    pub comm_r_last: H::Domain,
}

/// The candidate data, that is needed for ticket generation.
#[derive(Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub sector_id: SectorId,
    pub partial_ticket: Fr,
    pub ticket: [u8; 32],
    pub sector_challenge_index: u64,
}

impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("sector_id", &self.sector_id)
            .field("partial_ticket", &self.partial_ticket)
            .field("ticket", &hex::encode(&self.ticket))
            .field("sector_challenge_index", &self.sector_challenge_index)
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
    pub comm_q: H::Domain,
}

impl<H: Hasher> Proof<H> {
    pub fn leafs(&self) -> Vec<&H::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::leaf)
            .collect()
    }

    pub fn comm_r_last(&self) -> H::Domain {
        *self.inclusion_proofs[0].root()
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
    sector_size: u64,
    challenged_sectors: &[SectorId],
    trees: &BTreeMap<SectorId, MerkleTree<H::Domain, H::Function>>,
    prover_id: &[u8; 32],
    randomness: &[u8; 32],
) -> Result<Vec<Candidate>> {
    challenged_sectors
        .par_iter()
        .enumerate()
        .map(|(sector_challenge_index, sector_id)| {
            let tree = match trees.get(sector_id) {
                Some(tree) => tree,
                None => bail!(Error::MissingPrivateInput("tree", (*sector_id).into())),
            };

            generate_candidate::<H>(
                sector_size,
                tree,
                prover_id,
                *sector_id,
                randomness,
                sector_challenge_index as u64,
            )
        })
        .collect()
}

fn generate_candidate<H: Hasher>(
    sector_size: u64,
    tree: &MerkleTree<H::Domain, H::Function>,
    prover_id: &[u8; 32],
    sector_id: SectorId,
    randomness: &[u8; 32],
    sector_challenge_index: u64,
) -> Result<Candidate> {
    // 1. read the data for each challenge
    let mut data = vec![0u8; POST_CHALLENGE_COUNT * POST_CHALLENGED_NODES * NODE_SIZE];
    for n in 0..POST_CHALLENGE_COUNT {
        let challenge_start =
            generate_leaf_challenge(randomness, sector_challenge_index, n as u64, sector_size)?;

        let start = challenge_start as usize;
        let end = start + POST_CHALLENGED_NODES;

        tree.read_range_into(
            start,
            end,
            &mut data[n * POST_CHALLENGED_NODES * NODE_SIZE
                ..(n + 1) * POST_CHALLENGED_NODES * NODE_SIZE],
        )?;
    }

    // 2. Ticket generation

    // partial_ticket = pedersen(randomness | data | prover_id | sector_id)
    let mut sector_id_bytes = [0u8; 32];
    sector_id_bytes[..8].copy_from_slice(&u64::from(sector_id).to_le_bytes()[..]);
    let list: [&[u8]; 4] = [&randomness[..], &prover_id[..], &sector_id_bytes[..], &data];
    let bits = Bits::new_many(list.iter());

    let partial_ticket = pedersen_md_no_padding_bits(bits);

    // ticket = sha256(partial_ticket)
    let ticket = finalize_ticket(&partial_ticket);

    Ok(Candidate {
        sector_challenge_index,
        sector_id,
        partial_ticket,
        ticket,
    })
}

pub fn finalize_ticket(partial_ticket: &Fr) -> [u8; 32] {
    let bytes = fr_into_bytes::<Bls12>(partial_ticket);
    let ticket_hash = Sha256::digest(&bytes);
    let mut ticket = [0u8; 32];
    ticket.copy_from_slice(&ticket_hash[..]);
    ticket
}

pub fn is_valid_sector_challenge_index(challenge_count: u64, index: u64) -> bool {
    index < challenge_count
}

pub fn generate_sector_challenges(
    randomness: &[u8; 32],
    challenge_count: u64,
    sectors: &OrderedSectorSet,
) -> Result<Vec<SectorId>> {
    (0..challenge_count)
        .into_par_iter()
        .map(|n| generate_sector_challenge(randomness, n as usize, sectors))
        .collect()
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
        .context("invalid challenge generated")?;

    Ok(sector)
}

/// Generate all challenged leaf ranges for a single sector, such that the range fits into the sector.
pub fn generate_leaf_challenges(
    randomness: &[u8; 32],
    sector_challenge_index: u64,
    sector_size: u64,
) -> Result<Vec<u64>> {
    let mut challenges = Vec::with_capacity(POST_CHALLENGE_COUNT);

    for leaf_challenge_index in 0..POST_CHALLENGE_COUNT {
        let challenge = generate_leaf_challenge(
            randomness,
            sector_challenge_index,
            leaf_challenge_index as u64,
            sector_size,
        )?;
        challenges.push(challenge)
    }

    Ok(challenges)
}

/// Generates challenge, such that the range fits into the sector.
pub fn generate_leaf_challenge(
    randomness: &[u8; 32],
    sector_challenge_index: u64,
    leaf_challenge_index: u64,
    sector_size: u64,
) -> Result<u64> {
    ensure!(
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

    let challenged_range_index =
        leaf_challenge % (sector_size / (POST_CHALLENGED_NODES * NODE_SIZE) as u64);

    Ok(challenged_range_index * POST_CHALLENGED_NODES as u64)
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
            .into_par_iter()
            .flat_map(|n| {
                // TODO: replace unwrap with proper error handling
                let challenged_leaf_start = generate_leaf_challenge(
                    &pub_inputs.randomness,
                    pub_inputs.sector_challenge_index,
                    n as u64,
                    sector_size,
                )
                .unwrap();
                (0..POST_CHALLENGED_NODES).into_par_iter().map(move |i| {
                    Ok(MerkleProof::new_from_proof(
                        &tree.gen_proof(challenged_leaf_start as usize + i)?,
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        // 2. correct generation of the ticket from the partial_ticket (add this to the candidate)
        let ticket = finalize_ticket(&pub_inputs.partial_ticket);

        Ok(Proof {
            inclusion_proofs,
            ticket,
            comm_c: priv_inputs.comm_c,
            comm_q: priv_inputs.comm_q,
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let sector_size = pub_params.sector_size;

        // verify that H(Comm_c || comm_q || Comm_r_last) == Comm_R
        // comm_r_last is the root of the proof
        let comm_r_last = proof.inclusion_proofs[0].root();
        let comm_c = proof.comm_c;
        let comm_q = proof.comm_q;
        let comm_r = &pub_inputs.comm_r;

        if AsRef::<[u8]>::as_ref(&hash3(comm_c, comm_q, comm_r_last))
            != AsRef::<[u8]>::as_ref(comm_r)
        {
            return Ok(false);
        }

        for n in 0..POST_CHALLENGE_COUNT {
            let challenged_leaf_start = generate_leaf_challenge(
                &pub_inputs.randomness,
                pub_inputs.sector_challenge_index,
                n as u64,
                sector_size,
            )?;
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

                if !merkle_proof.validate(challenged_leaf_start as usize + i) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, PedersenHasher, Sha256Hasher};

    fn test_election_post<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = leaves * 32;

        let pub_params = PublicParams { sector_size };

        let randomness: [u8; 32] = rng.gen();
        let prover_id: [u8; 32] = rng.gen();

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = BTreeMap::new();
        for i in 0..5 {
            sectors.push(i.into());
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<H>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
            let tree = graph.merkle_tree(data.as_slice()).unwrap();
            trees.insert(i.into(), tree);
        }

        let candidates =
            generate_candidates::<H>(sector_size, &sectors, &trees, &prover_id, &randomness)
                .unwrap();

        let candidate = &candidates[0];
        let tree = trees.remove(&candidate.sector_id).unwrap();
        let comm_r_last = tree.root();
        let comm_c = H::Domain::random(rng);
        let comm_q = H::Domain::random(rng);
        let comm_r = Fr::from(hash3(comm_c, comm_q, comm_r_last)).into();

        let pub_inputs = PublicInputs {
            randomness,
            sector_id: candidate.sector_id,
            prover_id,
            comm_r,
            partial_ticket: candidate.partial_ticket,
            sector_challenge_index: 0,
        };

        let priv_inputs = PrivateInputs::<H> {
            tree,
            comm_c,
            comm_q,
            comm_r_last,
        };

        let proof = ElectionPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = ElectionPoSt::<H>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");

        assert!(is_valid);
    }

    #[test]
    fn election_post_pedersen() {
        test_election_post::<PedersenHasher>();
    }

    #[test]
    fn election_post_sha256() {
        test_election_post::<Sha256Hasher>();
    }

    #[test]
    fn election_post_blake2s() {
        test_election_post::<Blake2sHasher>();
    }
}
