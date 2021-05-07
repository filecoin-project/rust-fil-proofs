use std::marker::PhantomData;

use anyhow::ensure;
use filecoin_hashers::{Domain, Hasher};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    merkle::{MerkleProofTrait, MerkleTreeTrait},
    parameter_cache::ParameterSetMetadata,
    proof::{NoRequirements, ProofScheme},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProof<Proof: MerkleProofTrait> {
    #[serde(bound(
        serialize = "<Proof::Hasher as Hasher>::Domain: Serialize",
        deserialize = "<Proof::Hasher as Hasher>::Domain: Deserialize<'de>"
    ))]
    pub proof: Proof,
    #[serde(bound(
        serialize = "<Proof::Hasher as Hasher>::Domain: Serialize",
        deserialize = "<Proof::Hasher as Hasher>::Domain: Deserialize<'de>"
    ))]
    pub data: <Proof::Hasher as Hasher>::Domain,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs<T: Domain> {
    /// The root hash of the underlying merkle tree.
    #[serde(bound = "")]
    pub commitment: Option<T>,
    /// The challenge, which leaf to prove.
    pub challenge: usize,
}

/// The inputs that are only available to the prover.
#[derive(Debug)]
pub struct PrivateInputs<'a, Tree: MerkleTreeTrait> {
    /// The data of the leaf.
    pub leaf: <Tree::Hasher as Hasher>::Domain,
    /// The underlying merkle tree.
    pub tree: &'a Tree,
}

impl<'a, Tree: MerkleTreeTrait> PrivateInputs<'a, Tree> {
    pub fn new(leaf: <Tree::Hasher as Hasher>::Domain, tree: &'a Tree) -> Self {
        PrivateInputs { leaf, tree }
    }
}

#[derive(Clone, Debug)]
pub struct SetupParams {
    pub leaves: usize,
    pub private: bool,
}

/// Merkle tree based proof of retrievability.
#[derive(Debug, Default)]
pub struct PoR<Tree: MerkleTreeTrait> {
    _tree: PhantomData<Tree>,
}

impl<'a, Tree: 'a + MerkleTreeTrait> ProofScheme<'a> for PoR<Tree> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<<Tree::Hasher as Hasher>::Domain>;
    type PrivateInputs = PrivateInputs<'a, Tree>;
    type Proof = DataProof<Tree::Proof>;
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
        Ok(Self::Proof {
            proof,
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
                Some(ref commitment) => commitment == &proof.proof.root(),
                None => true,
            };

            let expected_path_length = proof.proof.expected_len(pub_params.leaves);
            let path_length_match = expected_path_length == proof.proof.path().len();

            if !(commitments_match && path_length_match) {
                dbg!(
                    commitments_match,
                    path_length_match,
                    expected_path_length,
                    proof.proof.path().len()
                );
                return Ok(false);
            }
        }

        let data_valid = proof.proof.validate_data(proof.data);
        let path_valid = proof.proof.validate(pub_inputs.challenge);

        Ok(data_valid && path_valid)
    }
}
