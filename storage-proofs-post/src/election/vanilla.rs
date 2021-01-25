use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use anyhow::{bail, ensure, Context};
use bellperson::bls::Fr;
use byteorder::{ByteOrder, LittleEndian};
use filecoin_hashers::{
    poseidon::{PoseidonDomain, PoseidonFunction},
    Domain, HashFunction, Hasher, PoseidonMDArity,
};
use fr32::fr_into_bytes;
use generic_array::typenum::Unsigned;
use log::trace;
use rayon::prelude::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelIterator,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_proofs_core::{
    error::{Error, Result},
    measurements::{measure_op, Operation},
    merkle::{MerkleProof, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
    parameter_cache::ParameterSetMetadata,
    proof::{NoRequirements, ProofScheme},
    sector::{OrderedSectorSet, SectorId},
    util::NODE_SIZE,
};

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
pub struct PrivateInputs<Tree: MerkleTreeTrait> {
    pub tree: MerkleTreeWrapper<
        Tree::Hasher,
        Tree::Store,
        Tree::Arity,
        Tree::SubTreeArity,
        Tree::TopTreeArity,
    >,
    pub comm_c: <Tree::Hasher as Hasher>::Domain,
    pub comm_r_last: <Tree::Hasher as Hasher>::Domain,
}

/// The candidate data, that is needed for ticket generation.
#[derive(Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub sector_id: SectorId,
    pub partial_ticket: Fr,
    pub ticket: [u8; 32],
    pub sector_challenge_index: u64,
}

impl Debug for Candidate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Candidate")
            .field("sector_id", &self.sector_id)
            .field("partial_ticket", &self.partial_ticket)
            .field("ticket", &hex::encode(&self.ticket))
            .field("sector_challenge_index", &self.sector_challenge_index)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<P: MerkleProofTrait> {
    #[serde(bound(
        serialize = "MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>: DeserializeOwned"
    ))]
    inclusion_proofs: Vec<MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>>,
    pub ticket: [u8; 32],
    pub comm_c: <P::Hasher as Hasher>::Domain,
}

impl<P: MerkleProofTrait> Proof<P> {
    pub fn leafs(&self) -> Vec<<P::Hasher as Hasher>::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::leaf)
            .collect()
    }

    pub fn comm_r_last(&self) -> <P::Hasher as Hasher>::Domain {
        self.inclusion_proofs[0].root()
    }

    pub fn commitments(&self) -> Vec<<P::Hasher as Hasher>::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::root)
            .collect()
    }

    #[allow(clippy::type_complexity)]
    pub fn paths(&self) -> Vec<Vec<(Vec<<P::Hasher as Hasher>::Domain>, usize)>> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::path)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ElectionPoSt<'a, Tree>
where
    Tree: MerkleTreeTrait,
{
    _t: PhantomData<&'a Tree>,
}

#[allow(clippy::type_complexity)]
pub fn generate_candidates<Tree: MerkleTreeTrait>(
    pub_params: &PublicParams,
    challenged_sectors: &[SectorId],
    trees: &BTreeMap<
        SectorId,
        MerkleTreeWrapper<
            Tree::Hasher,
            Tree::Store,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >,
    prover_id: <Tree::Hasher as Hasher>::Domain,
    randomness: <Tree::Hasher as Hasher>::Domain,
) -> Result<Vec<Candidate>> {
    challenged_sectors
        .par_iter()
        .enumerate()
        .map(|(sector_challenge_index, sector_id)| {
            let tree = match trees.get(sector_id) {
                Some(tree) => tree,
                None => bail!(Error::MissingPrivateInput("tree", (*sector_id).into())),
            };

            generate_candidate::<Tree>(
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

fn generate_candidate<Tree: MerkleTreeTrait>(
    pub_params: &PublicParams,
    tree: &MerkleTreeWrapper<
        Tree::Hasher,
        Tree::Store,
        Tree::Arity,
        Tree::SubTreeArity,
        Tree::TopTreeArity,
    >,
    prover_id: <Tree::Hasher as Hasher>::Domain,
    sector_id: SectorId,
    randomness: <Tree::Hasher as Hasher>::Domain,
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
    let bytes = fr_into_bytes(partial_ticket);
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
    hasher.update(AsRef::<[u8]>::as_ref(&randomness));
    hasher.update(&n.to_le_bytes()[..]);
    let hash = hasher.finalize();

    let sector_challenge = LittleEndian::read_u64(&hash[..8]);
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
    hasher.update(AsRef::<[u8]>::as_ref(&randomness));
    hasher.update(&sector_challenge_index.to_le_bytes()[..]);
    hasher.update(&leaf_challenge_index.to_le_bytes()[..]);
    let hash = hasher.finalize();

    let leaf_challenge = LittleEndian::read_u64(&hash[..8]);

    let challenged_range_index = leaf_challenge
        % (pub_params.sector_size / (pub_params.challenged_nodes * NODE_SIZE) as u64);

    Ok(challenged_range_index * pub_params.challenged_nodes as u64)
}

impl<'a, Tree: 'static + MerkleTreeTrait> ProofScheme<'a> for ElectionPoSt<'a, Tree> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<Tree::Hasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<Tree>;
    type Proof = Proof<Tree::Proof>;
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
            "Generating proof for tree of len {} with leafs {}",
            tree.len(),
            tree_leafs,
        );

        let inclusion_proofs = measure_op(Operation::PostInclusionProofs, || {
            (0..pub_params.challenge_count)
                .into_par_iter()
                .flat_map(|n| {
                    // TODO: replace expect with proper error handling
                    let challenged_leaf_start = generate_leaf_challenge(
                        pub_params,
                        pub_inputs.randomness,
                        pub_inputs.sector_challenge_index,
                        n as u64,
                    )
                    .expect("generate leaf challenge failure");
                    (0..pub_params.challenged_nodes)
                        .into_par_iter()
                        .map(move |i| {
                            tree.gen_cached_proof(challenged_leaf_start as usize + i, None)
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

        if AsRef::<[u8]>::as_ref(&<Tree::Hasher as Hasher>::Function::hash2(
            &comm_c,
            &comm_r_last,
        )) != AsRef::<[u8]>::as_ref(comm_r)
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
                    merkle_proof.expected_len(pub_params.sector_size as usize / NODE_SIZE);

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
