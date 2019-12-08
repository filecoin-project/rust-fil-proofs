use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;

use anyhow::{bail, ensure, Context};
use byteorder::{ByteOrder, LittleEndian};
use serde::{Deserialize, Serialize};

use crate::drgraph::graph_height;
use crate::error::{Error, Result};
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::proof::{NoRequirements, ProofScheme};
use crate::sector::*;
use crate::stacked::hash::hash2;
use crate::util::NODE_SIZE;

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

#[derive(Debug, Clone)]
pub struct RationalPoSt<'a, H>
where
    H: 'a + Hasher,
{
    _h: PhantomData<&'a H>,
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for RationalPoSt<'a, H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;
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
        let challenges = pub_inputs.challenges;

        let proofs = challenges
            .iter()
            .zip(priv_inputs.comm_r_lasts.iter())
            .map(|(challenge, comm_r_last)| {
                let challenged_leaf = challenge.leaf;

                if let Some(tree) = priv_inputs.trees.get(&challenge.sector) {
                    ensure!(comm_r_last == &tree.root(), Error::InvalidCommitment);

                    Ok(MerkleProof::new_from_proof(
                        &tree.gen_proof(challenged_leaf as usize)?,
                    ))
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
        let challenges = pub_inputs.challenges;

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

            if AsRef::<[u8]>::as_ref(&hash2(comm_c, comm_r_last)) != AsRef::<[u8]>::as_ref(&comm_r)
            {
                return Ok(false);
            }

            // validate the path length
            if graph_height(pub_params.sector_size as usize / NODE_SIZE)
                != merkle_proof.path().len()
            {
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    let hash = blake2b_simd::blake2b(&data);
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
    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, HashFunction, PedersenHasher, Sha256Hasher};
    use crate::merkle::make_proof_for_test;

    fn test_rational_post<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 8;

        let pub_params = PublicParams {
            sector_size,
            challenges_count,
        };

        let data1: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();
        let data2: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph1 = BucketGraph::<H>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
        let graph2 = BucketGraph::<H>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();
        let tree2 = graph2.merkle_tree(data2.as_slice()).unwrap();

        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let mut faults = OrderedSectorSet::new();
        faults.insert(139.into());
        faults.insert(1.into());
        faults.insert(32.into());

        let mut sectors = OrderedSectorSet::new();
        sectors.insert(891.into());
        sectors.insert(139.into());
        sectors.insert(32.into());
        sectors.insert(1.into());

        let mut trees = BTreeMap::new();
        trees.insert(139.into(), &tree1); // faulty with tree
        trees.insert(891.into(), &tree2);
        // other two faults don't have a tree available

        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();

        // the only valid sector to challenge is 891
        assert!(
            challenges.iter().all(|c| c.sector == 891.into()),
            "invalid challenge generated"
        );

        let comm_r_lasts = challenges
            .iter()
            .map(|c| trees.get(&c.sector).unwrap().root())
            .collect::<Vec<_>>();

        let comm_cs: Vec<H::Domain> = challenges.iter().map(|_c| H::Domain::random(rng)).collect();

        let comm_rs: Vec<H::Domain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| Fr::from(hash2(comm_c, comm_r_last)).into())
            .collect();

        let pub_inputs = PublicInputs {
            challenges: &challenges,
            comm_rs: &comm_rs,
            faults: &faults,
        };

        let priv_inputs = PrivateInputs::<H> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = RationalPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let is_valid = RationalPoSt::<H>::verify(&pub_params, &pub_inputs, &proof)
            .expect("verification failed");

        assert!(is_valid);
    }

    #[test]
    fn rational_post_pedersen() {
        test_rational_post::<PedersenHasher>();
    }

    #[test]
    fn rational_post_sha256() {
        test_rational_post::<Sha256Hasher>();
    }

    #[test]
    fn rational_post_blake2s() {
        test_rational_post::<Blake2sHasher>();
    }

    // Construct a proof that satisfies a cursory validation:
    // Data and proof are minimally consistent.
    // Proof root matches that requested in public inputs.
    // However, note that data has no relationship to anything,
    // and proof path does not actually prove that data was in the tree corresponding to expected root.
    fn make_bogus_proof<H: Hasher>(
        pub_inputs: &PublicInputs<H::Domain>,
        rng: &mut XorShiftRng,
    ) -> MerkleProof<H> {
        let bogus_leaf: H::Domain = H::Domain::random(rng);
        let hashed_leaf = H::Function::hash_leaf(&bogus_leaf);

        make_proof_for_test(
            pub_inputs.comm_rs[0],
            hashed_leaf,
            vec![(hashed_leaf, true)],
        )
    }

    fn test_rational_post_validates<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 2;
        let pub_params = PublicParams {
            sector_size,
            challenges_count,
        };

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph = BucketGraph::<H>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree = graph.merkle_tree(data.as_slice()).unwrap();
        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();

        let faults = OrderedSectorSet::new();
        let mut sectors = OrderedSectorSet::new();
        sectors.insert(0.into());
        sectors.insert(1.into());

        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let comm_r_lasts = challenges.iter().map(|_c| tree.root()).collect::<Vec<_>>();

        let comm_cs: Vec<H::Domain> = challenges.iter().map(|_c| H::Domain::random(rng)).collect();

        let comm_rs: Vec<H::Domain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| Fr::from(hash2(comm_c, comm_r_last)).into())
            .collect();

        let pub_inputs = PublicInputs::<H::Domain> {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let bad_proof = Proof {
            inclusion_proofs: vec![
                make_bogus_proof::<H>(&pub_inputs, rng),
                make_bogus_proof::<H>(&pub_inputs, rng),
            ],
            comm_cs,
        };

        let verified = RationalPoSt::verify(&pub_params, &pub_inputs, &bad_proof)
            .expect("verification failed");

        // A bad proof should not be verified!
        assert!(!verified);
    }

    #[test]
    fn rational_post_actually_validates_sha256() {
        test_rational_post_validates::<Sha256Hasher>();
    }

    #[test]
    fn rational_post_actually_validates_blake2s() {
        test_rational_post_validates::<Blake2sHasher>();
    }

    #[test]
    fn rational_post_actually_validates_pedersen() {
        test_rational_post_validates::<PedersenHasher>();
    }

    fn test_rational_post_validates_challenge_identity<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 2;

        let pub_params = PublicParams {
            sector_size,
            challenges_count,
        };

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph = BucketGraph::<H>::new(32, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree = graph.merkle_tree(data.as_slice()).unwrap();
        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let mut faults = OrderedSectorSet::new();
        faults.insert(1.into());
        let mut sectors = OrderedSectorSet::new();
        sectors.insert(0.into());
        sectors.insert(1.into());

        let mut trees = BTreeMap::new();
        trees.insert(0.into(), &tree);

        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let comm_r_lasts = challenges
            .iter()
            .map(|c| trees.get(&c.sector).unwrap().root())
            .collect::<Vec<_>>();

        let comm_cs: Vec<H::Domain> = challenges.iter().map(|_c| H::Domain::random(rng)).collect();

        let comm_rs: Vec<H::Domain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| Fr::from(hash2(comm_c, comm_r_last)).into())
            .collect();

        let pub_inputs = PublicInputs {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let priv_inputs = PrivateInputs::<H> {
            trees: &trees,
            comm_cs: &comm_cs,
            comm_r_lasts: &comm_r_lasts,
        };

        let proof = RationalPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let challenges =
            derive_challenges(challenges_count, sector_size, &sectors, &seed, &faults).unwrap();
        let comm_r_lasts = challenges.iter().map(|_c| tree.root()).collect::<Vec<_>>();

        let comm_cs: Vec<H::Domain> = challenges.iter().map(|_c| H::Domain::random(rng)).collect();

        let comm_rs: Vec<H::Domain> = comm_cs
            .iter()
            .zip(comm_r_lasts.iter())
            .map(|(comm_c, comm_r_last)| Fr::from(hash2(comm_c, comm_r_last)).into())
            .collect();

        let different_pub_inputs = PublicInputs {
            challenges: &challenges,
            faults: &faults,
            comm_rs: &comm_rs,
        };

        let verified = RationalPoSt::<H>::verify(&pub_params, &different_pub_inputs, &proof)
            .expect("verification failed");

        // A proof created with a the wrong challenge not be verified!
        assert!(!verified);
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_sha256() {
        test_rational_post_validates_challenge_identity::<Sha256Hasher>();
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_blake2s() {
        test_rational_post_validates_challenge_identity::<Blake2sHasher>();
    }

    #[test]
    fn rational_post_actually_validates_challenge_identity_pedersen() {
        test_rational_post_validates_challenge_identity::<PedersenHasher>();
    }

    #[test]
    fn test_derive_challenges_fails_on_all_faulty() {
        use std::collections::BTreeSet;

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
