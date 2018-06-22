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

impl<'a> ProofScheme<'a> for MerklePoR {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(_sp: &SetupParams) -> Result<PublicParams> {
        unimplemented!("not used");
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

        Ok(proof.proof.validate_data(&proof.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use drgraph::{Graph, Sampling};
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

        let graph = Graph::new(32, Some(Sampling::Bucket(16)));
        let tree = graph.merkle_tree(data.as_slice(), 32).unwrap();

        let pub_inputs = PublicInputs {
            challenge: 3,
            commitment: tree.root(),
        };

        let leaf = bytes_into_fr::<Bls12>(
            data_at_node(data.as_slice(), pub_inputs.challenge + 1, pub_params.lambda).unwrap(),
        ).unwrap();

        let priv_inputs = PrivateInputs { tree: &tree, leaf };

        let proof = MerklePoR::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

        assert!(MerklePoR::verify(&pub_params, &pub_inputs, &proof).unwrap());
    }
}
