use drgporep::DataProof;
use drgraph::{MerkleTree, TreeHash};
use error::Result;
use pairing::bls12_381::Fr;
use proof::ProofScheme;

/// The parameters shared between the prover and verifier.
#[derive(Debug)]
pub struct PublicParams {
    /// The size of a single leaf.
    pub lambda: usize,
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
}

/// The inputs that are necessary for the verifier to verify the proof.
#[derive(Debug)]
pub struct PublicInputs {
    /// The root hash of the underlying merkle tree.
    pub commitment: TreeHash,
    /// The challenge, which leaf to prove.
    pub challenge: usize,
}

/// The inputs that are only available to the prover.
#[derive(Debug)]
pub struct PrivateInputs<'a> {
    /// The data of the leaf.
    pub leaf: Fr,
    /// The underlying merkle tree.
    pub tree: &'a MerkleTree,
}

/// The proof that is returned from `prove`.
pub type Proof = DataProof;

#[derive(Debug)]
pub struct SetupParams {}

/// Merkle tree based proof of retrievability.
#[derive(Debug, Default)]
pub struct MerklePoR {}

const LAMBDA: usize = 32;
const LEAVES: usize = 32;

impl<'a> ProofScheme<'a> for MerklePoR {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(_sp: &SetupParams) -> Result<PublicParams> {
        Ok(PublicParams {
            lambda: LAMBDA,
            leaves: LEAVES,
        })
    }

    fn prove(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        priv_inputs: &Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let challenge = pub_inputs.challenge % pub_params.leaves;
        let tree = priv_inputs.tree;

        if pub_inputs.commitment != tree.root() {
            return Err(format_err!("tree root and commitment do not match"));
        }

        Ok(Proof {
            proof: tree.gen_proof(challenge).into(),
            data: priv_inputs.leaf,
        })
    }

    fn verify(
        _pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        if pub_inputs.commitment != proof.proof.root() {
            return Err(format_err!("invalid root"));
        }

        let data_valid = proof.proof.validate_data(&proof.data);
        let path_valid = proof.proof.validate(pub_inputs.challenge);

        Ok(data_valid && path_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use drgraph::{hash_leaf, make_proof_for_test, BucketGraph, Graph, DEFAULT_EXPANSION_DEGREE};
    use fr32::{bytes_into_fr, fr_into_bytes};
    use pairing::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use util::data_at_node;

    #[test]
    fn test_merklepor() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            lambda: 32,
            leaves: 32,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::new(32, 5, DEFAULT_EXPANSION_DEGREE);
        let tree = graph.merkle_tree(data.as_slice(), 32).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: tree.root(),
        };

        let leaf = bytes_into_fr::<Bls12>(
            data_at_node(data.as_slice(), pub_inputs.challenge, pub_params.lambda).unwrap(),
        ).unwrap();

        let priv_inputs = PrivateInputs { tree: &tree, leaf };

        let proof = MerklePoR::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(MerklePoR::verify(&pub_params, &pub_inputs, &proof).unwrap());
    }

    // Construct a proof that satisfies a cursory validation:
    // Data and proof are minimally consistent.
    // Proof root matches that requested in public inputs.
    // However, note that data has no relationship to anything,
    // and proof path does not actually prove that data was in the tree corresponding to expected root.
    fn make_bogus_proof(pub_inputs: &PublicInputs, rng: &mut XorShiftRng) -> DataProof {
        let bogus_leaf = bytes_into_fr::<Bls12>(&fr_into_bytes::<Bls12>(&rng.gen())).unwrap();
        let hashed_leaf = hash_leaf(&bogus_leaf);

        DataProof {
            data: bogus_leaf,
            proof: make_proof_for_test(
                pub_inputs.commitment,
                hashed_leaf,
                vec![(hashed_leaf, true)],
            ),
        }
    }

    #[test]
    fn test_merklepor_actually_validates() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            lambda: 32,
            leaves: 32,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::new(32, 5, 8);
        let tree = graph.merkle_tree(data.as_slice(), 32).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: tree.root(),
        };

        let bad_proof = make_bogus_proof(&pub_inputs, rng);

        let verified = MerklePoR::verify(&pub_params, &pub_inputs, &bad_proof).unwrap();

        // A bad proof should not be verified!
        assert!(!verified);
    }

    #[test]
    fn test_merklepor_validates_challenge_identity() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let pub_params = PublicParams {
            lambda: 32,
            leaves: 32,
        };

        let data: Vec<u8> = (0..32)
            .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
            .collect();

        let graph = BucketGraph::new(32, 5, 8);
        let tree = graph.merkle_tree(data.as_slice(), 32).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: tree.root(),
        };

        let leaf = bytes_into_fr::<Bls12>(
            data_at_node(data.as_slice(), pub_inputs.challenge, pub_params.lambda).unwrap(),
        ).unwrap();

        let priv_inputs = PrivateInputs { tree: &tree, leaf };

        let proof = MerklePoR::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        let different_pub_inputs = PublicInputs {
            challenge: 999,
            commitment: tree.root(),
        };

        let verified = MerklePoR::verify(&pub_params, &different_pub_inputs, &proof).unwrap();

        // A proof created with a the wrong challenge not be verified!
        assert!(!verified);
    }
}
