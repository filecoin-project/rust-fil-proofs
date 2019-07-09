use std::marker::PhantomData;

use crate::drgporep::DataProof;
use crate::drgraph::graph_height;
use crate::error::*;
use crate::hasher::Hasher;
use crate::hybrid_merkle::HybridMerkleTree;
use crate::merklepor;
use crate::proof::{NoRequirements, ProofScheme};

/// Inputs that are only available to the prover.
#[derive(Debug)]
pub struct PrivateInputs<'a, AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    /// The data of the leaf.
    pub leaf: BH::Domain,

    /// The underlying merkle tree.
    pub tree: &'a HybridMerkleTree<AH, BH>,

    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<'a, AH, BH> PrivateInputs<'a, AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    pub fn new(leaf: BH::Domain, tree: &'a HybridMerkleTree<AH, BH>) -> Self {
        PrivateInputs {
            leaf,
            tree,
            _ah: PhantomData,
            _bh: PhantomData,
        }
    }
}
/// Hybrid Merkle Tree based proof of retrievability.
#[derive(Debug, Default)]
pub struct HybridMerklePoR<AH, BH>
where
    AH: Hasher,
    BH: Hasher,
{
    _ah: PhantomData<AH>,
    _bh: PhantomData<BH>,
}

impl<'a, AH, BH> ProofScheme<'a> for HybridMerklePoR<AH, BH>
where
    AH: 'static + Hasher,
    BH: 'static + Hasher,
{
    type PublicParams = merklepor::PublicParams;
    type SetupParams = merklepor::SetupParams;
    type PublicInputs = merklepor::PublicInputs<AH::Domain>;
    type PrivateInputs = PrivateInputs<'a, AH, BH>;
    type Proof = DataProof<AH, BH>;
    type Requirements = NoRequirements;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(merklepor::PublicParams {
            leaves: sp.leaves,
            private: sp.private,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let tree = &priv_inputs.tree;

        if let Some(ref commitment) = pub_inputs.commitment {
            if commitment != &tree.root() {
                return Err(Error::InvalidCommitment);
            }
        }

        let challenge = pub_inputs.challenge % pub_params.leaves;

        Ok(DataProof {
            proof: tree.gen_proof(challenge),
            data: priv_inputs.leaf,
        })
    }

    fn verify(
        pub_params: &Self::PublicParams,
        pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let commitments_match = match pub_inputs.commitment {
            Some(ref commitment) => commitment == proof.proof.root(),
            None => true,
        };

        let path_length_match = graph_height(pub_params.leaves) == proof.proof.path_len();

        if !(commitments_match && path_length_match) {
            return Ok(false);
        }

        if !proof
            .proof
            .validate_challenge_value_as_bytes(proof.data.as_ref())
        {
            return Ok(false);
        }

        let is_valid = proof.proof.validate(pub_inputs.challenge);
        Ok(is_valid)
    }
}

// (jake) TODO: add tests
