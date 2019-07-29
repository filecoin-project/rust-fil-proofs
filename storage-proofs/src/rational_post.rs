use std::marker::PhantomData;

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::drgraph::graph_height;
use crate::error::{Error, Result};
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::proof::{NoRequirements, ProofScheme};

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
            "rationalPoSt::PublicParams{{sector_size: {} challenges_count: {}}}",
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
    pub challenges: &'a [u64],
    pub faults: &'a [u64],
    /// The root hashes of the underlying merkle trees.
    pub commitments: &'a [T],
}

#[derive(Debug, Clone)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub trees: &'a [&'a MerkleTree<H::Domain, H::Function>],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    inclusion_proofs: Vec<MerkleProof<H>>,
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
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let sector_size = pub_params.sector_size;
        let sector_count = priv_inputs.trees.len() as u64;

        assert_eq!(
            pub_inputs.challenges.len(),
            pub_inputs.commitments.len(),
            "missmatching challenges and commitments"
        );
        let challenges = pub_inputs.challenges;

        let proofs = challenges
            .iter()
            .zip(pub_inputs.commitments.iter())
            .map(|(challenge, commitment)| {
                let challenged_sector = *challenge % sector_count;
                let challenged_leaf = *challenge % (sector_size / 32);

                let tree = priv_inputs.trees[challenged_sector as usize];
                if commitment != &tree.root() {
                    return Err(Error::InvalidCommitment);
                }

                Ok(MerkleProof::new_from_proof(
                    &tree.gen_proof(challenged_leaf as usize),
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Proof {
            inclusion_proofs: proofs,
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let sector_size = pub_params.sector_size;

        let challenges = pub_inputs.challenges;

        if challenges.len() != pub_inputs.commitments.len() as usize {
            return Err(Error::MalformedInput);
        }

        if challenges.len() != proof.inclusion_proofs.len() {
            return Err(Error::MalformedInput);
        }

        // validate each proof
        for ((merkle_proof, challenge), commitment) in proof
            .inclusion_proofs
            .iter()
            .zip(challenges.iter())
            .zip(pub_inputs.commitments.iter())
        {
            let challenged_leaf = *challenge % (sector_size / 32);

            // validate the commitment
            if merkle_proof.root() != commitment {
                return Ok(false);
            }

            // validate the path length
            if graph_height(pub_params.sector_size as usize / 32) != merkle_proof.path().len() {
                return Ok(false);
            }

            if !merkle_proof.validate(challenged_leaf as usize) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Rational PoSt specific challenge derivation.
pub fn derive_challenges(count: usize, sector_size: u64, seed: &[u8], faults: &[u64]) -> Vec<u64> {
    // TODO: ensure sorting of faults
    (0..count)
        .map(|n| {
            let mut attempt = 0;
            loop {
                let c = derive_challenge(seed, n as u64, attempt);

                let challenged_sector = c % sector_size;

                // check for faulty sector
                if faults.binary_search(&challenged_sector).is_err() {
                    // valid challenge, not found
                    return c;
                }
                attempt += 1;
            }
        })
        .collect::<Vec<u64>>()
}

fn derive_challenge(seed: &[u8], n: u64, attempt: u64) -> u64 {
    let mut data = seed.to_vec();
    data.extend_from_slice(&n.to_le_bytes()[..]);
    data.extend_from_slice(&attempt.to_le_bytes()[..]);

    let big_challenge = BigUint::from_bytes_le(blake2b_simd::blake2b(&data).as_bytes());
    // TODO: is it correct to reduce the challenge already here?
    (big_challenge % std::u64::MAX)
        .to_u64()
        .expect("invalid mod to u64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, HashFunction, PedersenHasher, Sha256Hasher};
    use crate::merkle::make_proof_for_test;

    fn test_rational_post<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 8;

        let pub_params = PublicParams {
            sector_size,
            challenges_count,
        };

        let data1: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();
        let data2: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph1 = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let graph2 = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree1 = graph1.merkle_tree(data1.as_slice()).unwrap();
        let tree2 = graph2.merkle_tree(data2.as_slice()).unwrap();

        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let faults = vec![1];
        let challenges = derive_challenges(challenges_count, sector_size, &seed, &faults);
        let commitments = challenges
            .iter()
            .map(|c| {
                if c % 2 == 0 {
                    tree1.root()
                } else {
                    tree2.root()
                }
            })
            .collect::<Vec<_>>();

        let pub_inputs = PublicInputs {
            challenges: &challenges,
            commitments: &commitments,
            faults: &faults,
        };

        let priv_inputs = PrivateInputs::<H> {
            trees: &[&tree1, &tree2],
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
        let bogus_leaf: H::Domain = rng.gen();
        let hashed_leaf = H::Function::hash_leaf(&bogus_leaf);

        make_proof_for_test(
            pub_inputs.commitments[0],
            hashed_leaf,
            vec![(hashed_leaf, true)],
        )
    }

    fn test_rational_post_validates<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 2;
        let pub_params = PublicParams {
            sector_size,
            challenges_count,
        };

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();
        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let faults = vec![];
        let challenges = derive_challenges(challenges_count, sector_size, &seed, &faults);
        let commitments = challenges.iter().map(|_c| tree.root()).collect::<Vec<_>>();

        let pub_inputs = PublicInputs::<H::Domain> {
            challenges: &challenges,
            faults: &faults,
            commitments: &commitments,
        };

        let bad_proof = Proof {
            inclusion_proofs: vec![
                make_bogus_proof::<H>(&pub_inputs, rng),
                make_bogus_proof::<H>(&pub_inputs, rng),
            ],
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
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;
        let sector_size = leaves * 32;
        let challenges_count = 2;

        let pub_params = PublicParams {
            sector_size,
            challenges_count,
        };

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();
        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let faults = vec![1];
        let challenges = derive_challenges(challenges_count, sector_size, &seed, &faults);
        let commitments = challenges.iter().map(|_c| tree.root()).collect::<Vec<_>>();

        let pub_inputs = PublicInputs {
            challenges: &challenges,
            faults: &faults,
            commitments: &commitments,
        };

        let priv_inputs = PrivateInputs::<H> { trees: &[&tree] };

        let proof = RationalPoSt::<H>::prove(&pub_params, &pub_inputs, &priv_inputs)
            .expect("proving failed");

        let seed = (0..32).map(|_| rng.gen()).collect::<Vec<u8>>();
        let challenges = derive_challenges(challenges_count, sector_size, &seed, &faults);
        let commitments = challenges.iter().map(|_c| tree.root()).collect::<Vec<_>>();

        let different_pub_inputs = PublicInputs {
            challenges: &challenges,
            faults: &faults,
            commitments: &commitments,
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
}
