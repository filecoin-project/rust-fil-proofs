use drgporep::DataProof;
use drgraph::{MerkleTree, TreeAlgorithm};
use error::Result;
use proof::ProofScheme;
use util::data_at_node;

#[derive(Debug)]
pub struct PublicParams {
    pub lambda: usize,
    pub leaves: usize,
}

#[derive(Debug)]
pub struct PublicInputs {
    pub challenge: usize,
}

#[derive(Debug)]
pub struct PrivateInputs<'a> {
    pub data: &'a [u8],
    pub tree: &'a MerkleTree,
}

pub type Proof<'a> = DataProof<'a>;

#[derive(Debug)]
pub struct SetupParams {}

/// Merkle Proof of Retrievability
#[derive(Debug)]
pub struct MerklePoR {}

impl<'a> ProofScheme<'a> for MerklePoR {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof<'a>;

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

        let data = data_at_node(priv_inputs.data, challenge + 1, pub_params.lambda)?;

        Ok(Proof {
            proof: tree.gen_proof(challenge),
            data: data,
        })
    }

    fn verify(
        _pub_params: &Self::PublicParams,
        _pub_inputs: &Self::PublicInputs,
        proof: &Self::Proof,
    ) -> Result<bool> {
        // TODO: check hash of the replicaNode.data matches hash

        if !proof.proof.validate::<TreeAlgorithm>() {
            Ok(false)
        } else {
            Ok(true)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use drgraph::{Graph, Sampling};

    #[test]
    fn test_merklepor() {
        let pub_params = PublicParams {
            lambda: 16,
            leaves: 32,
        };
        let pub_inputs = PublicInputs { challenge: 3 };

        let data = vec![3u8; 16 * 32];
        let graph = Graph::new(32, Some(Sampling::Bucket(16)));
        let tree = graph.merkle_tree(data.as_slice(), 16).unwrap();

        let priv_inputs = PrivateInputs {
            tree: &tree,
            data: data.as_slice(),
        };

        let proof = MerklePoR::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();
        assert!(MerklePoR::verify(&pub_params, &pub_inputs, &proof).unwrap());
    }
}
