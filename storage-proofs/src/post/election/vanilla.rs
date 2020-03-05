use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use anyhow::{bail, ensure, Context};
use byteorder::{ByteOrder, LittleEndian};
use generic_array::typenum;
use log::trace;
use merkletree::store::StoreConfig;
use paired::bls12_381::{Bls12, Fr};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use typenum::Unsigned;

use crate::drgraph::graph_height;
use crate::error::{Error, Result};
use crate::fr32::fr_into_bytes;
use crate::hasher::{
    Domain, HashFunction, Hasher, PoseidonDomain, PoseidonFunction, PoseidonMDArity,
};
use crate::measurements::{measure_op, Operation};
use crate::merkle::{MerkleProof, OctLCMerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::porep::stacked::OCT_ARITY;
use crate::proof::{NoRequirements, ProofScheme};
use crate::sector::*;
use crate::util::NODE_SIZE;

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
    pub challenge_count: usize,
    pub challenged_nodes: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    /// Size of the sector in bytes.
    pub sector_size: u64,
    pub challenge_count: usize,
    pub challenged_nodes: usize,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!(
            "ElectionPoSt::PublicParams{{sector_size: {}, count: {}, nodes: {}}}",
            self.sector_size(),
            self.challenge_count,
            self.challenged_nodes,
        )
    }

    fn sector_size(&self) -> u64 {
        self.sector_size
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    pub randomness: T,
    pub sector_id: SectorId,
    pub prover_id: T,
    pub comm_r: T,
    pub partial_ticket: Fr,
    pub sector_challenge_index: u64,
}

#[derive(Debug)]
pub struct PrivateInputs<H: Hasher> {
    pub tree: OctLCMerkleTree<H::Domain, H::Function>,
    pub comm_c: H::Domain,
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
        serialize = "MerkleProof<H, typenum::U8>: Serialize",
        deserialize = "MerkleProof<H, typenum::U8>: Deserialize<'de>"
    ))]
    inclusion_proofs: Vec<MerkleProof<H, typenum::U8>>,
    pub ticket: [u8; 32],
    pub comm_c: H::Domain,
}

impl<H: Hasher> Proof<H> {
    pub fn leafs(&self) -> Vec<H::Domain> {
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

    #[allow(clippy::type_complexity)]
    pub fn paths(&self) -> Vec<&Vec<(Vec<H::Domain>, usize)>> {
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
    trees: &BTreeMap<SectorId, OctLCMerkleTree<H::Domain, H::Function>>,
    prover_id: H::Domain,
    randomness: H::Domain,
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
                pub_params,
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
    pub_params: &PublicParams,
    tree: &OctLCMerkleTree<H::Domain, H::Function>,
    prover_id: H::Domain,
    sector_id: SectorId,
    randomness: H::Domain,
    sector_challenge_index: u64,
) -> Result<Candidate> {
    let randomness_fr: Fr = randomness.into();
    let prover_id_fr: Fr = prover_id.into();
    let mut data: Vec<PoseidonDomain> = vec![
        randomness_fr.into(),
        prover_id_fr.into(),
        Fr::from(sector_id).into(),
    ];

    for n in 0..pub_params.challenge_count {
        let challenge =
            generate_leaf_challenge(pub_params, randomness, sector_challenge_index, n as u64)?;

        let val: Fr = measure_op(Operation::PostReadChallengedRange, || {
            tree.read_at(challenge as usize)
        })?
        .into();
        data.push(val.into());
    }

    // pad for md
    let arity = PoseidonMDArity::to_usize();
    while data.len() % arity != 0 {
        data.push(PoseidonDomain::default());
    }

    let partial_ticket: Fr = measure_op(Operation::PostPartialTicketHash, || {
        PoseidonFunction::hash_md(&data)
    })
    .into();

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

pub fn generate_sector_challenges<T: Domain>(
    randomness: T,
    challenge_count: u64,
    sectors: &OrderedSectorSet,
) -> Result<Vec<SectorId>> {
    (0..challenge_count)
        .into_par_iter()
        .map(|n| generate_sector_challenge(randomness, n as usize, sectors))
        .collect()
}

pub fn generate_sector_challenge<T: Domain>(
    randomness: T,
    n: usize,
    sectors: &OrderedSectorSet,
) -> Result<SectorId> {
    let mut hasher = Sha256::new();
    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
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
pub fn generate_leaf_challenges<T: Domain>(
    pub_params: &PublicParams,
    randomness: T,
    sector_challenge_index: u64,
    challenge_count: usize,
) -> Result<Vec<u64>> {
    let mut challenges = Vec::with_capacity(challenge_count);

    for leaf_challenge_index in 0..challenge_count {
        let challenge = generate_leaf_challenge(
            pub_params,
            randomness,
            sector_challenge_index,
            leaf_challenge_index as u64,
        )?;
        challenges.push(challenge)
    }

    Ok(challenges)
}

/// Generates challenge, such that the range fits into the sector.
pub fn generate_leaf_challenge<T: Domain>(
    pub_params: &PublicParams,
    randomness: T,
    sector_challenge_index: u64,
    leaf_challenge_index: u64,
) -> Result<u64> {
    ensure!(
        pub_params.sector_size > pub_params.challenged_nodes as u64 * NODE_SIZE as u64,
        "sector size {} is too small",
        pub_params.sector_size
    );

    let mut hasher = Sha256::new();
    hasher.input(AsRef::<[u8]>::as_ref(&randomness));
    hasher.input(&sector_challenge_index.to_le_bytes()[..]);
    hasher.input(&leaf_challenge_index.to_le_bytes()[..]);
    let hash = hasher.result();

    let leaf_challenge = LittleEndian::read_u64(&hash.as_ref()[..8]);

    let challenged_range_index = leaf_challenge
        % (pub_params.sector_size / (pub_params.challenged_nodes * NODE_SIZE) as u64);

    Ok(challenged_range_index * pub_params.challenged_nodes as u64)
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
            challenge_count: sp.challenge_count,
            challenged_nodes: sp.challenged_nodes,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        // 1. Inclusions proofs of all challenged leafs in all challenged ranges
        let tree = &priv_inputs.tree;
        let tree_leafs = tree.leafs();

        trace!(
            "Generating proof for tree of len {} with leafs {}, and cached_layers {}",
            tree.len(),
            tree_leafs,
            StoreConfig::default_cached_above_base_layer(tree_leafs, OCT_ARITY)
        );
        let inclusion_proofs = measure_op(Operation::PostInclusionProofs, || {
            (0..pub_params.challenge_count)
                .into_par_iter()
                .flat_map(|n| {
                    // TODO: replace unwrap with proper error handling
                    let challenged_leaf_start = generate_leaf_challenge(
                        pub_params,
                        pub_inputs.randomness,
                        pub_inputs.sector_challenge_index,
                        n as u64,
                    )
                    .unwrap();
                    (0..pub_params.challenged_nodes)
                        .into_par_iter()
                        .map(move |i| {
                            let config_levels =
                                StoreConfig::default_cached_above_base_layer(tree_leafs, OCT_ARITY);
                            let proof = {
                                if config_levels == 0 {
                                    tree.gen_proof(challenged_leaf_start as usize + i)?
                                } else {
                                    let (proof, _) = tree.gen_proof_and_partial_tree(
                                        challenged_leaf_start as usize + i,
                                        config_levels,
                                    )?;

                                    proof
                                }
                            };
                            Ok(MerkleProof::new_from_proof(&proof))
                        })
                })
                .collect::<Result<Vec<_>>>()
        })?;

        // 2. correct generation of the ticket from the partial_ticket (add this to the candidate)
        let ticket = measure_op(Operation::PostFinalizeTicket, || {
            finalize_ticket(&pub_inputs.partial_ticket)
        });

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
        // verify that H(Comm_c || Comm_r_last) == Comm_R
        // comm_r_last is the root of the proof
        let comm_r_last = proof.inclusion_proofs[0].root();
        let comm_c = proof.comm_c;
        let comm_r = &pub_inputs.comm_r;

        if AsRef::<[u8]>::as_ref(&H::Function::hash2(&comm_c, comm_r_last))
            != AsRef::<[u8]>::as_ref(comm_r)
        {
            return Ok(false);
        }

        for n in 0..pub_params.challenge_count {
            let challenged_leaf_start = generate_leaf_challenge(
                pub_params,
                pub_inputs.randomness,
                pub_inputs.sector_challenge_index,
                n as u64,
            )?;
            for i in 0..pub_params.challenged_nodes {
                let merkle_proof = &proof.inclusion_proofs[n * pub_params.challenged_nodes + i];

                // validate all comm_r_lasts match
                if merkle_proof.root() != comm_r_last {
                    return Ok(false);
                }

                // validate the path length
                let expected_path_length =
                    graph_height::<typenum::U8>(pub_params.sector_size as usize / NODE_SIZE) - 1;
                if expected_path_length != merkle_proof.path().len() {
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

    use std::fs::File;
    use std::io::prelude::*;

    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{PedersenHasher, PoseidonHasher};

    fn test_election_post<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let sector_size = leaves * NODE_SIZE;

        let pub_params = PublicParams {
            sector_size: sector_size as u64,
            challenge_count: 40,
            challenged_nodes: 1,
        };

        let randomness = H::Domain::random(rng);
        let prover_id = H::Domain::random(rng);

        let mut sectors: Vec<SectorId> = Vec::new();
        let mut trees = BTreeMap::new();

        // Construct and store an MT using a named DiskStore.
        let temp_dir = tempdir::TempDir::new("level_cache_tree").unwrap();
        let temp_path = temp_dir.path();
        let config = StoreConfig::new(
            &temp_path,
            String::from("test-lc-tree"),
            StoreConfig::default_cached_above_base_layer(leaves as usize, OCT_ARITY),
        );

        for i in 0..5 {
            sectors.push(i.into());
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
                .collect();

            let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();

            let replica_path = temp_path.join(format!("replica-path-{}", i));
            let mut f = File::create(&replica_path).unwrap();
            f.write_all(&data).unwrap();

            let cur_config = StoreConfig::from_config(&config, format!("test-lc-tree-{}", i), None);
            let lctree: OctLCMerkleTree<_, _> = graph
                .lcmerkle_tree(cur_config.clone(), &data, &replica_path)
                .unwrap();
            trees.insert(i.into(), lctree);
        }

        let candidates =
            generate_candidates::<H>(&pub_params, &sectors, &trees, prover_id, randomness).unwrap();

        let candidate = &candidates[0];
        let tree = trees.remove(&candidate.sector_id).unwrap();
        let comm_r_last = tree.root();
        let comm_c = H::Domain::random(rng);
        let comm_r = H::Function::hash2(&comm_c, &comm_r_last);

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
    fn election_post_poseidon() {
        test_election_post::<PoseidonHasher>();
    }
}
