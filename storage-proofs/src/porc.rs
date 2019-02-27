use std::marker::PhantomData;

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use serde::de::Deserialize;
use serde::ser::Serialize;

use crate::drgraph::graph_height;
use crate::error::{Error, Result};
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetIdentifier;
use crate::proof::ProofScheme;

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
    /// The number of sectors that are proven over.
    pub sectors_count: usize,
    /// How many challenges there are in total.
    pub challenges_count: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    // NOTE: This assumes all sectors are the same size, which may not remain a valid assumption.
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
    /// The number of sectors that are proven over.
    pub sectors_count: usize,
    /// How many challenges there are in total.
    pub challenges_count: usize,
}

impl ParameterSetIdentifier for PublicParams {
    fn parameter_set_identifier(&self) -> String {
        format!(
            "porc::PublicParams{{leaves: {} sectors_count: {} challenges_count: {}}}",
            self.leaves, self.sectors_count, self.challenges_count,
        )
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<'a, T: 'a + Domain> {
    /// The challenges, which leafs to prove.
    pub challenges: &'a [usize],
    pub challenged_sectors: &'a [usize],
    /// The root hashes of the underlying merkle trees.
    pub commitments: &'a [T],
}

#[derive(Debug, Clone)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub trees: &'a [&'a MerkleTree<H::Domain, H::Function>],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher>(
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>"
    ))]
    Vec<MerkleProof<H>>,
);

impl<H: Hasher> Proof<H> {
    pub fn leafs(&self) -> Vec<&H::Domain> {
        self.0.iter().map(MerkleProof::leaf).collect()
    }

    pub fn commitments(&self) -> Vec<&H::Domain> {
        self.0.iter().map(MerkleProof::root).collect()
    }

    pub fn paths(&self) -> Vec<&Vec<(H::Domain, bool)>> {
        self.0.iter().map(MerkleProof::path).collect()
    }
}

#[derive(Debug, Clone)]
pub struct PoRC<'a, H>
where
    H: 'a + Hasher,
{
    _h: PhantomData<&'a H>,
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for PoRC<'a, H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            leaves: sp.leaves,
            sectors_count: sp.sectors_count,
            challenges_count: sp.challenges_count,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        if priv_inputs.trees.len() != pub_params.sectors_count {
            return Err(Error::MalformedInput);
        }

        if priv_inputs.trees.len() != pub_params.sectors_count {
            return Err(Error::MalformedInput);
        }

        if pub_inputs.challenges.len() != pub_params.challenges_count {
            return Err(Error::MalformedInput);
        }

        if pub_inputs.challenged_sectors.len() != pub_params.challenges_count {
            return Err(Error::MalformedInput);
        }

        let proofs = pub_inputs
            .challenges
            .iter()
            .zip(pub_inputs.challenged_sectors)
            .map(|(challenged_leaf, challenged_sector)| {
                let tree = priv_inputs.trees[*challenged_sector];

                if pub_inputs.commitments[*challenged_sector] != tree.root() {
                    return Err(Error::InvalidCommitment);
                }

                Ok(MerkleProof::new_from_proof(
                    &tree.gen_proof(*challenged_leaf),
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Proof(proofs))
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        if pub_inputs.challenges.len() != pub_params.challenges_count {
            return Err(Error::MalformedInput);
        }

        if pub_inputs.challenged_sectors.len() != pub_params.challenges_count {
            return Err(Error::MalformedInput);
        }

        // validate each proof
        for (merkle_proof, (challenged_leaf, challenged_sector)) in proof.0.iter().zip(
            pub_inputs
                .challenges
                .iter()
                .zip(pub_inputs.challenged_sectors.iter()),
        ) {
            // validate the commitment
            if merkle_proof.root() != &pub_inputs.commitments[*challenged_sector] {
                return Ok(false);
            }

            // validate the path length
            if graph_height(pub_params.leaves) != merkle_proof.path().len() {
                return Ok(false);
            }

            if !merkle_proof.validate(*challenged_leaf) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

pub fn slice_mod(challenge: impl AsRef<[u8]>, count: usize) -> usize {
    // TODO: verify this is the correct way to derive the challenge
    let big_challenge = BigUint::from_bytes_be(challenge.as_ref());

    (big_challenge % count)
        .to_usize()
        .expect("failed modulus operation")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::drgraph::{new_seed, BucketGraph, Graph};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{Blake2sHasher, HashFunction, PedersenHasher, Sha256Hasher};
    use crate::merkle::make_proof_for_test;

    fn test_porc<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;
        let pub_params = PublicParams {
            leaves,
            sectors_count: 1,
            challenges_count: 2,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenges: &vec![rng.gen_range(0, leaves), rng.gen_range(0, leaves)],
            challenged_sectors: &[0, 0],
            commitments: &[tree.root()],
        };

        let priv_inputs = PrivateInputs::<H> { trees: &[&tree] };

        let proof = PoRC::<H>::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(PoRC::<H>::verify(&pub_params, &pub_inputs, &proof).unwrap());
    }

    #[test]
    fn porc_pedersen() {
        test_porc::<PedersenHasher>();
    }

    #[test]
    fn porc_sha256() {
        test_porc::<Sha256Hasher>();
    }

    #[test]
    fn porc_blake2s() {
        test_porc::<Blake2sHasher>();
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

    fn test_porc_validates<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            leaves: 32,
            sectors_count: 1,
            challenges_count: 2,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        let pub_inputs = PublicInputs::<H::Domain> {
            challenges: &vec![rng.gen(), rng.gen()],
            challenged_sectors: &[0, 0],
            commitments: &[tree.root()],
        };

        let bad_proof = Proof(vec![
            make_bogus_proof::<H>(&pub_inputs, rng),
            make_bogus_proof::<H>(&pub_inputs, rng),
        ]);

        let verified = PoRC::verify(&pub_params, &pub_inputs, &bad_proof).unwrap();

        // A bad proof should not be verified!
        assert!(!verified);
    }

    #[test]
    fn porc_actually_validates_sha256() {
        test_porc_validates::<Sha256Hasher>();
    }

    #[test]
    fn porc_actually_validates_blake2s() {
        test_porc_validates::<Blake2sHasher>();
    }

    #[test]
    fn porc_actually_validates_pedersen() {
        test_porc_validates::<PedersenHasher>();
    }

    fn test_porc_validates_challenge_identity<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 32;

        let pub_params = PublicParams {
            leaves,
            sectors_count: 1,
            challenges_count: 2,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenges: &vec![rng.gen_range(0, leaves), rng.gen_range(0, leaves)],
            challenged_sectors: &[0, 0],
            commitments: &[tree.root()],
        };

        let priv_inputs = PrivateInputs::<H> { trees: &[&tree] };

        let proof = PoRC::<H>::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        let different_pub_inputs = PublicInputs {
            challenges: &vec![rng.gen_range(0, leaves), rng.gen_range(0, leaves)],
            challenged_sectors: &[0, 0],
            commitments: &[tree.root()],
        };

        let verified = PoRC::<H>::verify(&pub_params, &different_pub_inputs, &proof).unwrap();

        // A proof created with a the wrong challenge not be verified!
        assert!(!verified);
    }

    #[test]
    fn porc_actually_validates_challenge_identity_sha256() {
        test_porc_validates_challenge_identity::<Sha256Hasher>();
    }

    #[test]
    fn porc_actually_validates_challenge_identity_blake2s() {
        test_porc_validates_challenge_identity::<Blake2sHasher>();
    }

    #[test]
    fn porc_actually_validates_challenge_identity_pedersen() {
        test_porc_validates_challenge_identity::<PedersenHasher>();
    }

    #[test]
    fn test_slice_mod() {
        let cases: [(Vec<u8>, usize, usize); 5] = [
            (vec![0], 10, 0),
            (vec![1], 10, 1),
            (vec![9], 10, 9),
            (vec![10], 10, 0),
            (vec![100, 0, 0, 1], 10, 1),
        ];

        for (challenge, count, expected) in &cases {
            assert_eq!(slice_mod(challenge, *count), *expected);
        }
    }
}
