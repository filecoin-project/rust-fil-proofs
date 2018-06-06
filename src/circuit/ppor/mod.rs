use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::JubjubEngine;
use sapling_crypto::primitives::ValueCommitment;

use circuit::por::proof_of_retrievability;

/// This is an instance of the `ParallelProofOfRetrievability` circuit.
pub struct ParallelProofOfRetrievability<'a, E: JubjubEngine> {
    pub params: &'a E::Params,

    /// Pedersen commitment to the value.
    pub value_commitments: Vec<Option<ValueCommitment<E>>>,

    /// The authentication path of the commitment in the tree.
    pub auth_paths: Vec<Vec<Option<(E::Fr, bool)>>>,

    /// The root
    pub root: Option<E::Fr>,
}

impl<'a, E: JubjubEngine> Circuit<E> for ParallelProofOfRetrievability<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // TODO: bring back
        // assert_eq!(self.value_commitments.len(), self.auth_paths.len());

        for i in 0..self.value_commitments.len() {
            let mut ns = cs.namespace(|| format!("round: {}", i));
            proof_of_retrievability(
                &mut ns,
                self.params,
                self.value_commitments[i].clone(),
                self.auth_paths[i].clone(),
                self.root.clone(),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use hasher::pedersen::merkle_tree_from_u64;
    use pairing::Field;
    use pairing::bls12_381::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;

    #[test]
    fn test_parallel_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let par_depth = 16;

        // TODO: go for 10, currently pretty slow
        for _ in 0..1 {
            let value_commitments: Vec<Option<_>> = (0..par_depth)
                .map(|_| {
                    Some(ValueCommitment {
                        value: rng.gen(),
                        randomness: rng.gen(),
                    })
                })
                .collect();
            let values = value_commitments
                .iter()
                .map(|v| v.clone().unwrap().value)
                .collect();

            let tree = merkle_tree_from_u64(values);
            let auth_paths: Vec<Vec<Option<(Fr, bool)>>> = (0..par_depth)
                .map(|i| {
                    let merkle_proof = tree.gen_proof(i);
                    // below we construct the auth_path, such that it matches the expecations
                    // of our circuit
                    let auth_path: Vec<Option<(Fr, bool)>> = merkle_proof
                    .lemma()
                    .iter()
                    .skip(1) // the lemma has the leaf as first elemtn, need to skip
                    .zip(merkle_proof.path().iter())
                    .map(|(hash, is_left)| Some(((*hash).into(), !is_left)))
                    .collect::<Vec<Option<(Fr, bool)>>>();
                    auth_path
                })
                .collect();

            let root = tree.root();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let instance = ParallelProofOfRetrievability {
                params: params,
                value_commitments: value_commitments.clone(),
                auth_paths: auth_paths.clone(),
                root: Some(root.into()),
            };

            instance.synthesize(&mut cs).unwrap();

            assert!(cs.is_satisfied());

            assert_eq!(cs.num_inputs(), 49); // depends on how many leafs we prove
            assert_eq!(cs.get_input(0, "ONE"), Fr::one());
            assert_eq!(cs.get_input(3, "round: 0/root/input variable"), root.into());
        }
    }
}
