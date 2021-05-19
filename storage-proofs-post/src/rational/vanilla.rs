use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;

use anyhow::{bail, ensure, Context};
use blake2b_simd::blake2b;
use byteorder::{ByteOrder, LittleEndian};
use filecoin_hashers::{Domain, HashFunction, Hasher};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use storage_proofs_core::{
    error::{Error, Result},
    merkle::{MerkleProof, MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper},
    parameter_cache::ParameterSetMetadata,
    proof::{NoRequirements, ProofScheme},
    sector::{OrderedSectorSet, SectorId},
    util::NODE_SIZE,
};

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// The size of a sector.
    pub sector_size: u64,
    // TODO: can we drop this?
    /// How many challenges there are in total.
    pub challenges_count: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    /// The size of a sector.
    pub sector_size: u64,
    /// How many challenges there are in total.
    pub challenges_count: usize,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!(
            "RationalPoSt::PublicParams{{sector_size: {} challenges_count: {}}}",
            self.sector_size(),
            self.challenges_count,
        )
    }

    fn sector_size(&self) -> u64 {
        self.sector_size
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs<T: Domain> {
    /// The challenges, which leafs to prove.
    pub challenges: Vec<Challenge>,
    pub faults: OrderedSectorSet,
    #[serde(bound = "")]
    pub comm_rs: Vec<T>,
}

#[derive(Debug, Clone)]
#[allow(clippy::type_complexity)]
pub struct PrivateInputs<'a, Tree: 'a + MerkleTreeTrait> {
    pub trees: &'a BTreeMap<
        SectorId,
        &'a MerkleTreeWrapper<
            Tree::Hasher,
            Tree::Store,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >,
    pub comm_cs: &'a Vec<<Tree::Hasher as Hasher>::Domain>,
    pub comm_r_lasts: &'a Vec<<Tree::Hasher as Hasher>::Domain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<P: MerkleProofTrait> {
    #[serde(bound(
        serialize = "MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>: DeserializeOwned"
    ))]
    inclusion_proofs: Vec<MerkleProof<P::Hasher, P::Arity, P::SubTreeArity, P::TopTreeArity>>,
    pub comm_cs: Vec<<P::Hasher as Hasher>::Domain>,
}

impl<P: MerkleProofTrait> Proof<P> {
    pub fn leafs(&self) -> Vec<<P::Hasher as Hasher>::Domain> {
        self.inclusion_proofs
            .iter()
            .map(MerkleProof::leaf)
            .collect()
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
pub struct RationalPoSt<'a, Tree>
where
    Tree: MerkleTreeTrait,
{
    _t: PhantomData<&'a Tree>,
}

impl<'a, Tree: 'a + MerkleTreeTrait> ProofScheme<'a> for RationalPoSt<'a, Tree> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<Tree::Hasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<'a, Tree>;
    type Proof = Proof<Tree::Proof>;
    type Requirements = NoRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            sector_size: sp.sector_size,
            challenges_count: sp.challenges_count,
        })
    }

    fn prove<'b>(
        _pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        ensure!(
            pub_inputs.challenges.len() == pub_inputs.comm_rs.len(),
            "mismatched challenges and comm_rs"
        );
        ensure!(
            pub_inputs.challenges.len() == priv_inputs.comm_cs.len(),
            "mismatched challenges and comm_cs"
        );
        ensure!(
            pub_inputs.challenges.len() == priv_inputs.comm_r_lasts.len(),
            "mismatched challenges and comm_r_lasts"
        );
        let challenges = &pub_inputs.challenges;

        let proofs = challenges
            .iter()
            .zip(priv_inputs.comm_r_lasts.iter())
            .map(|(challenge, comm_r_last)| {
                let challenged_leaf = challenge.leaf;

                if let Some(tree) = priv_inputs.trees.get(&challenge.sector) {
                    ensure!(comm_r_last == &tree.root(), Error::InvalidCommitment);

                    tree.gen_cached_proof(challenged_leaf as usize, None)
                } else {
                    bail!(Error::MalformedInput);
                }
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Proof {
            inclusion_proofs: proofs,
            comm_cs: priv_inputs.comm_cs.to_vec(),
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let challenges = &pub_inputs.challenges;

        ensure!(
            challenges.len() == pub_inputs.comm_rs.len() as usize,
            Error::MalformedInput
        );

        ensure!(
            challenges.len() == proof.inclusion_proofs.len(),
            Error::MalformedInput
        );

        // validate each proof
        for (((merkle_proof, challenge), comm_r), comm_c) in proof
            .inclusion_proofs
            .iter()
            .zip(challenges.iter())
            .zip(pub_inputs.comm_rs.iter())
            .zip(proof.comm_cs.iter())
        {
            let challenged_leaf = challenge.leaf;

            // verify that H(Comm_c || Comm_r_last) == Comm_R
            // comm_r_last is the root of the proof
            let comm_r_last = merkle_proof.root();

            if AsRef::<[u8]>::as_ref(&<Tree::Hasher as Hasher>::Function::hash2(
                comm_c,
                &comm_r_last,
            )) != AsRef::<[u8]>::as_ref(&comm_r)
            {
                return Ok(false);
            }

            // validate the path length
            let expected_path_length =
                merkle_proof.expected_len(pub_params.sector_size as usize / NODE_SIZE);

            if expected_path_length != merkle_proof.path().len() {
                return Ok(false);
            }

            if !merkle_proof.validate(challenged_leaf as usize) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// A challenge specifying a sector and leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    // The identifier of the challenged sector.
    pub sector: SectorId,
    // The leaf index this challenge points at.
    pub leaf: u64,
}

/// Rational PoSt specific challenge derivation.
pub fn derive_challenges(
    challenge_count: usize,
    sector_size: u64,
    sectors: &OrderedSectorSet,
    seed: &[u8],
    faults: &OrderedSectorSet,
) -> Result<Vec<Challenge>> {
    (0..challenge_count)
        .map(|n| {
            let mut attempt = 0;
            let mut attempted_sectors = HashSet::new();
            loop {
                let c = derive_challenge(seed, n as u64, attempt, sector_size, sectors)?;

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
        .collect()
}

fn derive_challenge(
    seed: &[u8],
    n: u64,
    attempt: u64,
    sector_size: u64,
    sectors: &OrderedSectorSet,
) -> Result<Challenge> {
    let mut data = seed.to_vec();
    data.extend_from_slice(&n.to_le_bytes()[..]);
    data.extend_from_slice(&attempt.to_le_bytes()[..]);

    let hash = blake2b(&data);
    let challenge_bytes = hash.as_bytes();
    let sector_challenge = LittleEndian::read_u64(&challenge_bytes[..8]);
    let leaf_challenge = LittleEndian::read_u64(&challenge_bytes[8..16]);

    let sector_index = (sector_challenge % sectors.len() as u64) as usize;
    let sector = *sectors
        .iter()
        .nth(sector_index)
        .context("invalid challenge generated")?;

    Ok(Challenge {
        sector,
        leaf: leaf_challenge % (sector_size / NODE_SIZE as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    #[test]
    fn test_derive_challenges_fails_on_all_faulty() {
        let mut sectors = BTreeSet::new();
        sectors.insert(SectorId::from(1));
        sectors.insert(SectorId::from(2));

        let mut faults = BTreeSet::new();
        faults.insert(SectorId::from(1));
        faults.insert(SectorId::from(2));

        let seed = vec![0u8];

        assert!(derive_challenges(10, 1024, &sectors, &seed, &faults).is_err());
    }
}
