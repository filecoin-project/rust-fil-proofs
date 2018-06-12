use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::jubjub::JubjubEngine;

use circuit::por::proof_of_retrievability;

/// This is an instance of the `ParallelProofOfRetrievability` circuit.
pub struct ParallelProofOfRetrievability<'a, E: JubjubEngine> {
    pub params: &'a E::Params,

    /// Pedersen commitment to the value.
    pub value_commitments: Vec<Option<&'a [u8]>>,

    pub commitment_size: usize,

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
    use pairing::bls12_381::*;
    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;
    use util::data_at_node;

    #[test]
    fn test_parallel_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let par_depth = 16;
        let commitment_size = 32;

        for _ in 0..5 {
            let data: Vec<u8> = (0..commitment_size * par_depth)
                .map(|_| rng.gen())
                .collect();

            let value_commitments: Vec<Option<_>> = (0..par_depth)
                .map(|i| Some(data_at_node(data.as_slice(), i + 1, commitment_size).unwrap()))
                .collect();

            let graph = drgraph::Graph::new(par_depth, None);
            let tree = graph.merkle_tree(data.as_slice(), commitment_size).unwrap();

            let auth_paths: Vec<Vec<Option<(Fr, bool)>>> = (0..par_depth)
                .map(|i| proof_into_options(tree.gen_proof(i)))
                .collect();

            let root = tree.root();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let instance = ParallelProofOfRetrievability {
                params,
                commitment_size,
                value_commitments: value_commitments,
                auth_paths: auth_paths.clone(),
                root: Some(root.into()),
            };

            instance
                .synthesize(&mut cs)
                .expect("failed to synthesize circuit");

            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 17, "wrong number of inputs");
            assert_eq!(cs.get_input(0, "ONE"), Fr::one());
            assert_eq!(cs.get_input(1, "round: 0/root/input variable"), root.into());
            assert_eq!(cs.get_input(2, "round: 1/root/input variable"), root.into());
            assert_eq!(cs.get_input(3, "round: 2/root/input variable"), root.into());

            assert_eq!(
                cs.get_input(16, "round: 15/root/input variable"),
                root.into()
            );
        }
    }
}
