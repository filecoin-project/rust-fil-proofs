use std::marker::PhantomData;

use crate::drgporep::DataProof;
use crate::drgraph::graph_height;
use crate::error::*;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetIdentifier;
use crate::proof::ProofScheme;

/// The parameters shared between the prover and verifier.
#[derive(Clone, Debug)]
pub struct PublicParams {
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
    pub private: bool,
}

impl ParameterSetIdentifier for PublicParams {
    fn parameter_set_identifier(&self) -> String {
        format!(
            "merklepor::PublicParams{{leaves: {}; private: {}}}",
            self.leaves, self.private
        )
    }
}

/// The inputs that are necessary for the verifier to verify the proof.
#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain> {
    /// The root hash of the underlying merkle tree.
    pub commitment: Option<T>,
    /// The challenge, which leaf to prove.
    pub challenge: usize,
}

/// The inputs that are only available to the prover.
#[derive(Debug)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    /// The data of the leaf.
    pub leaf: H::Domain,
    /// The underlying merkle tree.
    pub tree: &'a MerkleTree<H::Domain, H::Function>,
    _h: PhantomData<H>,
}

impl<'a, H: Hasher> PrivateInputs<'a, H> {
    pub fn new(leaf: H::Domain, tree: &'a MerkleTree<H::Domain, H::Function>) -> Self {
        PrivateInputs {
            leaf,
            tree,
            _h: PhantomData,
        }
    }
}

/// The proof that is returned from `prove`.
pub type Proof<H> = DataProof<H>;

#[derive(Debug)]
pub struct SetupParams {
    pub leaves: usize,
    pub private: bool,
}

/// Merkle tree based proof of retrievability.
#[derive(Debug, Default)]
pub struct MerklePoR<H: Hasher> {
    _h: PhantomData<H>,
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for MerklePoR<H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;

    fn setup(sp: &SetupParams) -> Result<PublicParams> {
        Ok(PublicParams {
            leaves: sp.leaves,
            private: sp.private,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let challenge = pub_inputs.challenge % pub_params.leaves;
        let tree = priv_inputs.tree;

        if let Some(ref commitment) = pub_inputs.commitment {
            if commitment != &tree.root() {
                return Err(Error::InvalidCommitment);
            }
        }

        Ok(Proof {
            proof: MerkleProof::new_from_proof(&tree.gen_proof(challenge)),
            data: priv_inputs.leaf,
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        {
            // This was verify_proof_meta.
            let commitments_match = match pub_inputs.commitment {
                Some(ref commitment) => commitment == proof.proof.root(),
                None => true,
            };

            let path_length_match = graph_height(pub_params.leaves) == proof.proof.path().len();

            if !(commitments_match && path_length_match) {
                return Ok(false);
            }
        }
        let data_valid = proof.proof.validate_data(&proof.data.into_bytes());
        let path_valid = proof.proof.validate(pub_inputs.challenge);

        Ok(data_valid && path_valid)
    }
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
    use crate::util::data_at_node;

    fn test_merklepor<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            leaves: 32,
            private: false,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        let leaf =
            H::Domain::try_from_bytes(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap())
                .unwrap();

        let priv_inputs = PrivateInputs::<H>::new(leaf, &tree);

        let proof = MerklePoR::<H>::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(MerklePoR::<H>::verify(&pub_params, &pub_inputs, &proof).unwrap());
    }

    #[test]
    fn merklepor_pedersen() {
        test_merklepor::<PedersenHasher>();
    }

    #[test]
    fn merklepor_sha256() {
        test_merklepor::<Sha256Hasher>();
    }

    #[test]
    fn merklepor_blake2s() {
        test_merklepor::<Blake2sHasher>();
    }

    // Construct a proof that satisfies a cursory validation:
    // Data and proof are minimally consistent.
    // Proof root matches that requested in public inputs.
    // However, note that data has no relationship to anything,
    // and proof path does not actually prove that data was in the tree corresponding to expected root.
    fn make_bogus_proof<H: Hasher>(
        pub_inputs: &PublicInputs<H::Domain>,
        rng: &mut XorShiftRng,
    ) -> DataProof<H> {
        let bogus_leaf: H::Domain = rng.gen();
        let hashed_leaf = H::Function::hash_leaf(&bogus_leaf);

        DataProof {
            data: bogus_leaf,
            proof: make_proof_for_test(
                pub_inputs.commitment.unwrap(),
                hashed_leaf,
                vec![(hashed_leaf, true)],
            ),
        }
    }

    fn test_merklepor_validates<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            leaves: 32,
            private: false,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        let bad_proof = make_bogus_proof::<H>(&pub_inputs, rng);

        let verified = MerklePoR::verify(&pub_params, &pub_inputs, &bad_proof).unwrap();

        // A bad proof should not be verified!
        assert!(!verified);
    }

    #[test]
    fn merklepor_actually_validates_sha256() {
        test_merklepor_validates::<Sha256Hasher>();
    }

    #[test]
    fn merklepor_actually_validates_blake2s() {
        test_merklepor_validates::<Blake2sHasher>();
    }

    #[test]
    fn merklepor_actually_validates_pedersen() {
        test_merklepor_validates::<PedersenHasher>();
    }

    fn test_merklepor_validates_challenge_identity<H: Hasher>() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            leaves: 32,
            private: false,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::<H>::new(32, 5, 0, new_seed());
        let tree = graph.merkle_tree(data.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        let leaf =
            H::Domain::try_from_bytes(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap())
                .unwrap();

        let priv_inputs = PrivateInputs::<H>::new(leaf, &tree);

        let proof = MerklePoR::<H>::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        let different_pub_inputs = PublicInputs {
            challenge: 999,
            commitment: Some(tree.root()),
        };

        let verified = MerklePoR::<H>::verify(&pub_params, &different_pub_inputs, &proof).unwrap();

        // A proof created with a the wrong challenge not be verified!
        assert!(!verified);
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_sha256() {
        test_merklepor_validates_challenge_identity::<Sha256Hasher>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_blake2s() {
        test_merklepor_validates_challenge_identity::<Blake2sHasher>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_pedersen() {
        test_merklepor_validates_challenge_identity::<PedersenHasher>();
    }
}
