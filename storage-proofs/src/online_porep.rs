use std::marker::PhantomData;

use num_bigint::BigUint;
use num_traits::ToPrimitive;

use drgraph::graph_height;
use error::*;
use hasher::{Domain, Hasher};
use merkle::{MerkleProof, MerkleTree};
use parameter_cache::ParameterSetIdentifier;
use proof::ProofScheme;

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// The size of a single leaf.
    pub lambda: usize,
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    /// The size of a single leaf.
    pub lambda: usize,
    /// How many leaves the underlying merkle tree has.
    pub leaves: usize,
}

impl ParameterSetIdentifier for PublicParams {
    fn parameter_set_identifier(&self) -> String {
        format!(
            "online_drgporep::PublicParams{{lambda: {}; leaves: {}}}",
            self.lambda, self.leaves,
        )
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<'a, T: Domain> {
    /// The challenge, which leafs to prove.
    pub challenges: &'a [T],
    /// The root hash of the underlying merkle tree.
    pub commitment: T,
}

#[derive(Debug, Clone)]
pub struct PrivateInputs<'a, H: 'a + Hasher> {
    pub replica: &'a [u8],
    pub tree: &'a MerkleTree<H::Domain, H::Function>,
}

#[derive(Debug, Clone)]
pub struct Proof<H: Hasher>(Vec<MerkleProof<H>>);

impl<H: Hasher> Proof<H> {
    pub fn leafs(&self) -> Vec<&H::Domain> {
        self.0.iter().map(|p| p.leaf()).collect()
    }
}

#[derive(Debug, Clone)]
pub struct OnlinePoRep<H: Hasher> {
    _h: PhantomData<H>,
}

impl<'a, H: 'a + Hasher> ProofScheme<'a> for OnlinePoRep<H> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, H::Domain>;
    type PrivateInputs = PrivateInputs<'a, H>;
    type Proof = Proof<H>;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            lambda: sp.lambda,
            leaves: sp.leaves,
        })
    }

    fn prove<'b>(
        pub_params: &'b Self::PublicParams,
        pub_inputs: &'b Self::PublicInputs,
        priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        let proofs = pub_inputs
            .challenges
            .iter()
            .map(|challenge| {
                // challenge derivation
                let challenged_leaf = get_leaf(challenge, pub_params.leaves);
                let tree = priv_inputs.tree;

                if pub_inputs.commitment != tree.root() {
                    return Err(Error::InvalidCommitment);
                }

                Ok(MerkleProof::new_from_proof(
                    &tree.gen_proof(challenged_leaf),
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
        // validate each proof
        for (merkle_proof, challenge) in proof.0.iter().zip(pub_inputs.challenges.iter()) {
            // validate the commitment
            if merkle_proof.root() != &pub_inputs.commitment {
                return Ok(false);
            }

            // validate the path length
            if graph_height(pub_params.leaves) != merkle_proof.path().len() {
                return Ok(false);
            }

            let challenged_leaf = get_leaf(challenge, pub_params.leaves);
            if !merkle_proof.validate(challenged_leaf) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

fn get_leaf(challenge: impl AsRef<[u8]>, count: usize) -> usize {
    // TODO: verify this is the correct way to derive the challenge
    let big_challenge = BigUint::from_bytes_be(challenge.as_ref());

    (big_challenge % count)
        .to_usize()
        .expect("failed modulus operation")
}
