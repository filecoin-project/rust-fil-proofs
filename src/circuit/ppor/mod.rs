use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::JubjubEngine;

use circuit::por::proof_of_retrievability;

/// This is an instance of the `ParallelProofOfRetrievability` circuit.
pub struct ParallelProofOfRetrievability<'a, E: JubjubEngine> {
    /// Paramters for the engine.
    pub params: &'a E::Params,

    /// Pedersen commitment to the value.
    pub value_commitments: Vec<Option<&'a [u8]>>,

    /// The size of a single commitment in bits.
    pub commitment_size: usize,

    /// The authentication path of the commitment in the tree.
    pub auth_paths: Vec<Vec<Option<(E::Fr, bool)>>>,

    /// The root of the underyling merkle tree.
    pub root: Option<E::Fr>,
}

impl<'a, E: JubjubEngine> Circuit<E> for ParallelProofOfRetrievability<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert_eq!(self.value_commitments.len(), self.auth_paths.len());

        for i in 0..self.value_commitments.len() {
            let mut ns = cs.namespace(|| format!("round: {}", i));
            proof_of_retrievability(
                &mut ns,
                self.params,
                self.value_commitments[i],
                self.commitment_size,
                self.auth_paths[i].clone(),
                self.root,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use drgraph::{self, proof_into_options};
    use merklepor;
    use pairing::bls12_381::*;
    use pairing::Field;
    use proof::ProofScheme;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;
    use util::data_at_node;

    #[test]
    fn test_parallel_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 16;
        let lambda = 32;
        let pub_params = merklepor::PublicParams { lambda, leaves };

        for _ in 0..5 {
            let data: Vec<u8> = (0..lambda * leaves).map(|_| rng.gen()).collect();

            let graph = drgraph::Graph::new(leaves, None);
            let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

            let pub_inputs: Vec<_> = (0..leaves)
                .map(|i| merklepor::PublicInputs {
                    challenge: i,
                    commitment: tree.root(),
                })
                .collect();
            let priv_inputs: Vec<_> = (0..leaves)
                .map(|i| merklepor::PrivateInputs {
                    tree: &tree,
                    leaf: data_at_node(
                        data.as_slice(),
                        pub_inputs[i].challenge + 1,
                        pub_params.lambda,
                    ).unwrap(),
                })
                .collect();

            let proofs: Vec<_> = (0..leaves)
                .map(|i| {
                    merklepor::MerklePoR::prove(&pub_params, &pub_inputs[i], &priv_inputs[i])
                        .unwrap()
                })
                .collect();

            for i in 0..leaves {
                // make sure it verifies
                assert!(
                    merklepor::MerklePoR::verify(&pub_params, &pub_inputs[i], &proofs[i]).unwrap(),
                    "failed to verify merklepor proof"
                );
            }

            let auth_paths: Vec<_> = proofs.iter().map(|p| p.proof.as_options()).collect();
            let value_commitments: Vec<_> = proofs.iter().map(|p| Some(p.data)).collect();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let instance = ParallelProofOfRetrievability {
                params,
                commitment_size: pub_params.lambda,
                value_commitments: value_commitments,
                auth_paths: auth_paths,
                root: Some(tree.root().into()),
            };

            instance
                .synthesize(&mut cs)
                .expect("failed to synthesize circuit");

            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 33, "wrong number of inputs");
            assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        }
    }
}
