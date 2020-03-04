use std::marker::PhantomData;

use anyhow::ensure;
use generic_array::typenum;
use serde::{Deserialize, Serialize};

use crate::drgraph::graph_height;
use crate::error::*;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::proof::{NoRequirements, ProofScheme};

#[derive(Clone, Serialize, Deserialize)]
pub struct DataProof<H: Hasher, U: typenum::Unsigned> {
    #[serde(bound(
        serialize = "MerkleProof<H, U>: Serialize",
        deserialize = "MerkleProof<H, U>: Deserialize<'de>"
    ))]
    pub proof: MerkleProof<H, U>,
    pub data: H::Domain,
}

impl<H: Hasher, U: typenum::Unsigned> std::fmt::Debug for DataProof<H, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerkleProof")
            .field("proof", &self.proof)
            .field("data", &self.data)
            .field("H", &H::name())
            .field("U", &U::to_usize())
            .finish()
    }
}

/// The parameters shared between the prover and verifier.
#[derive(Clone, Debug)]
pub struct PublicParams {
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
    pub private: bool,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!(
            "merklepor::PublicParams{{leaves: {}; private: {}}}",
            self.leaves, self.private
        )
    }

    fn sector_size(&self) -> u64 {
        unimplemented!("required for parameter metadata file generation")
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
pub struct PrivateInputs<'a, H: 'a + Hasher, U: typenum::Unsigned> {
    /// The data of the leaf.
    pub leaf: H::Domain,
    /// The underlying merkle tree.
    pub tree: &'a MerkleTree<H::Domain, H::Function, U>,
    _h: PhantomData<H>,
}

impl<'a, H: Hasher, U: typenum::Unsigned> PrivateInputs<'a, H, U> {
    pub fn new(leaf: H::Domain, tree: &'a MerkleTree<H::Domain, H::Function, U>) -> Self {
        PrivateInputs {
            leaf,
            tree,
            _h: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SetupParams {
    pub leaves: usize,
    pub private: bool,
}

/// Merkle tree based proof of retrievability.
#[derive(Debug, Default)]
pub struct PoR<H: Hasher, U: typenum::Unsigned> {
    _h: PhantomData<H>,
    _u: PhantomData<U>,
}

impl<'a, H: 'a + Hasher, U: 'a + typenum::Unsigned + Sync + Send + Clone> ProofScheme<'a>
    for PoR<H, U>
{
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H, U>;
    type Proof = DataProof<H, U>;
    type Requirements = NoRequirements;

    fn setup(sp: &SetupParams) -> Result<PublicParams> {
        // atm only binary trees are implemented
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
            ensure!(commitment == &tree.root(), Error::InvalidCommitment);
        }
        let proof = tree.gen_proof(challenge)?;

        Ok(DataProof {
            proof: MerkleProof::new_from_proof(&proof),
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

            let expected_path_length = graph_height::<U>(pub_params.leaves) - 1;
            let path_length_match = expected_path_length == proof.proof.path().len();

            if !(commitments_match && path_length_match) {
                return Ok(false);
            }
        }

        let data_valid = proof.proof.validate_data(proof.data);
        let path_valid = proof.proof.validate(pub_inputs.challenge);

        Ok(data_valid && path_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::drgraph::{new_seed, BucketGraph, Graph, BASE_DEGREE};
    use crate::fr32::fr_into_bytes;
    use crate::hasher::{
        Blake2sHasher, HashFunction, PedersenHasher, PoseidonHasher, Sha256Hasher,
    };
    use crate::merkle::make_proof_for_test;
    use crate::util::data_at_node;

    fn test_merklepor<H: Hasher, U: 'static + typenum::Unsigned + Clone + Send + Sync>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 16;
        let pub_params = PublicParams {
            leaves,
            private: false,
        };

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree = graph.merkle_tree(None, data.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        let leaf =
            H::Domain::try_from_bytes(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap())
                .unwrap();

        let priv_inputs = PrivateInputs::<H, U>::new(leaf, &tree);

        let proof =
            PoR::<H, U>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

        let is_valid =
            PoR::<H, U>::verify(&pub_params, &pub_inputs, &proof).expect("verification failed");

        assert!(is_valid);
    }

    #[test]
    fn merklepor_pedersen_binary() {
        test_merklepor::<PedersenHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_poseidon_binary() {
        test_merklepor::<PoseidonHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_sha256_binary() {
        test_merklepor::<Sha256Hasher, typenum::U2>();
    }

    #[test]
    fn merklepor_blake2s_binary() {
        test_merklepor::<Blake2sHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_pedersen_quad() {
        test_merklepor::<PedersenHasher, typenum::U4>();
    }

    #[test]
    fn merklepor_poseidon_quad() {
        test_merklepor::<PoseidonHasher, typenum::U4>();
    }

    #[test]
    fn merklepor_sha256_quad() {
        test_merklepor::<Sha256Hasher, typenum::U4>();
    }

    #[test]
    fn merklepor_blake2s_quad() {
        test_merklepor::<Blake2sHasher, typenum::U4>();
    }

    // Construct a proof that satisfies a cursory validation:
    // Data and proof are minimally consistent.
    // Proof root matches that requested in public inputs.
    // However, note that data has no relationship to anything,
    // and proof path does not actually prove that data was in the tree corresponding to expected root.
    fn make_bogus_proof<H: Hasher, U: typenum::Unsigned>(
        pub_inputs: &PublicInputs<H::Domain>,
        rng: &mut XorShiftRng,
    ) -> DataProof<H, U> {
        let bogus_leaf: H::Domain = H::Domain::random(rng);
        let hashed_leaf = H::Function::hash_leaf(&bogus_leaf);

        DataProof {
            data: bogus_leaf,
            proof: make_proof_for_test(
                pub_inputs.commitment.unwrap(),
                hashed_leaf,
                vec![(vec![hashed_leaf; U::to_usize() - 1], 1)],
            ),
        }
    }

    fn test_merklepor_validates<H: Hasher, U: typenum::Unsigned + 'static + Clone + Sync + Send>() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;
        let pub_params = PublicParams {
            leaves,
            private: false,
        };

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree: MerkleTree<_, _, U> = graph.merkle_tree(None, data.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        let bad_proof = make_bogus_proof::<H, U>(&pub_inputs, rng);

        let verified =
            PoR::verify(&pub_params, &pub_inputs, &bad_proof).expect("verification failed");

        // A bad proof should not be verified!
        assert!(!verified);
    }

    #[test]
    fn merklepor_actually_validates_sha256_binary() {
        test_merklepor_validates::<Sha256Hasher, typenum::U2>();
    }

    #[test]
    fn merklepor_actually_validates_blake2s_binary() {
        test_merklepor_validates::<Blake2sHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_actually_validates_pedersen_binary() {
        test_merklepor_validates::<PedersenHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_actually_validates_poseidon_binary() {
        test_merklepor_validates::<PoseidonHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_actually_validates_sha256_quad() {
        test_merklepor_validates::<Sha256Hasher, typenum::U4>();
    }

    #[test]
    fn merklepor_actually_validates_blake2s_quad() {
        test_merklepor_validates::<Blake2sHasher, typenum::U4>();
    }

    #[test]
    fn merklepor_actually_validates_pedersen_quad() {
        test_merklepor_validates::<PedersenHasher, typenum::U4>();
    }

    #[test]
    fn merklepor_actually_validates_poseidon_quad() {
        test_merklepor_validates::<PoseidonHasher, typenum::U4>();
    }

    fn test_merklepor_validates_challenge_identity<
        H: Hasher,
        U: typenum::Unsigned + 'static + Clone + Send + Sync,
    >() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = 64;

        let pub_params = PublicParams {
            leaves,
            private: false,
        };

        let data: Vec<u8> = (0..leaves)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let graph = BucketGraph::<H>::new(leaves, BASE_DEGREE, 0, new_seed()).unwrap();
        let tree = graph.merkle_tree(None, data.as_slice()).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: Some(tree.root()),
        };

        let leaf =
            H::Domain::try_from_bytes(data_at_node(data.as_slice(), pub_inputs.challenge).unwrap())
                .unwrap();

        let priv_inputs = PrivateInputs::<H, U>::new(leaf, &tree);

        let proof =
            PoR::<H, U>::prove(&pub_params, &pub_inputs, &priv_inputs).expect("proving failed");

        let different_pub_inputs = PublicInputs {
            challenge: 999,
            commitment: Some(tree.root()),
        };

        let verified = PoR::<H, U>::verify(&pub_params, &different_pub_inputs, &proof)
            .expect("verification failed");

        // A proof created with a the wrong challenge not be verified!
        assert!(!verified);
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_sha256_binary() {
        test_merklepor_validates_challenge_identity::<Sha256Hasher, typenum::U2>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_blake2s_binary() {
        test_merklepor_validates_challenge_identity::<Blake2sHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_pedersen_binary() {
        test_merklepor_validates_challenge_identity::<PedersenHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_poseidon_binary() {
        test_merklepor_validates_challenge_identity::<PoseidonHasher, typenum::U2>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_sha256_quad() {
        test_merklepor_validates_challenge_identity::<Sha256Hasher, typenum::U4>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_blake2s_quad() {
        test_merklepor_validates_challenge_identity::<Blake2sHasher, typenum::U4>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_pedersen_quad() {
        test_merklepor_validates_challenge_identity::<PedersenHasher, typenum::U4>();
    }

    #[test]
    fn merklepor_actually_validates_challenge_identity_poseidon_quad() {
        test_merklepor_validates_challenge_identity::<PoseidonHasher, typenum::U4>();
    }
}
