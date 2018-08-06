use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::{boolean, multipack, num, pedersen_hash};
use sapling_crypto::jubjub::JubjubEngine;

/// This is an instance of the `ParallelProofOfRetrievability` circuit.
///
/// # Public Inputs
///
/// This circuit expects the following public inputs.
///
/// * for i in 0..values.len()
///   * [0] - packed version of `value` as bits. (might be more than one Fr)
///   * [1] - packed version of the `is_right` components of the auth_path.
///   * [2] - the merkle root of the tree.
pub struct ParallelProofOfRetrievability<'a, E: JubjubEngine> {
    /// Paramters for the engine.
    pub params: &'a E::Params,

    /// Pedersen commitment to the value.
    pub values: Vec<Option<E::Fr>>,

    /// The authentication path of the commitment in the tree.
    pub auth_paths: Vec<Vec<Option<(E::Fr, bool)>>>,

    /// The root of the underyling merkle tree.
    pub root: Option<E::Fr>,
}

impl<'a, E: JubjubEngine> Circuit<E> for ParallelProofOfRetrievability<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert_eq!(self.values.len(), self.auth_paths.len());

        let real_root_value = self.root;

        // Allocate the "real" root that will be exposed.
        let rt = num::AllocatedNum::alloc(cs.namespace(|| "root value"), || {
            real_root_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        for i in 0..self.values.len() {
            let mut cs = cs.namespace(|| format!("round {}", i));
            let params = self.params;
            let value = self.values[i];
            let auth_path = self.auth_paths[i].clone();

            let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value"), || {
                value.ok_or_else(|| SynthesisError::AssignmentMissing)
            })?;

            value_num.inputize(cs.namespace(|| "value num"))?;

            let mut value_bits = value_num.into_bits_le(cs.namespace(|| "value bits"))?;

            // sad face, need to pad to make all algorithms the same
            while value_bits.len() < 256 {
                value_bits.push(boolean::Boolean::Constant(false));
            }

            // Compute the hash of the value
            let cm = pedersen_hash::pedersen_hash(
                cs.namespace(|| "value hash"),
                pedersen_hash::Personalization::NoteCommitment,
                &value_bits,
                params,
            )?;

            // This is an injective encoding, as cur is a
            // point in the prime order subgroup.
            let mut cur = cm.get_x().clone();

            let mut auth_path_bits = Vec::with_capacity(auth_path.len());

            // Ascend the merkle tree authentication path
            for (i, e) in auth_path.into_iter().enumerate() {
                let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

                // Determines if the current subtree is the "right" leaf at this
                // depth of the tree.
                let cur_is_right = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                    cs.namespace(|| "position bit"),
                    e.map(|e| e.1),
                )?);

                // Witness the authentication path element adjacent
                // at this depth.
                let path_element =
                    num::AllocatedNum::alloc(cs.namespace(|| "path element"), || {
                        Ok(e.ok_or(SynthesisError::AssignmentMissing)?.0)
                    })?;

                // Swap the two if the current subtree is on the right
                let (xl, xr) = num::AllocatedNum::conditionally_reverse(
                    cs.namespace(|| "conditional reversal of preimage"),
                    &cur,
                    &path_element,
                    &cur_is_right,
                )?;

                // We don't need to be strict, because the function is
                // collision-resistant. If the prover witnesses a congruency,
                // they will be unable to find an authentication path in the
                // tree with high probability.
                let mut preimage = vec![];
                preimage.extend(xl.into_bits_le(cs.namespace(|| "xl into bits"))?);
                preimage.extend(xr.into_bits_le(cs.namespace(|| "xr into bits"))?);

                // Compute the new subtree value
                cur = pedersen_hash::pedersen_hash(
                    cs.namespace(|| "computation of pedersen hash"),
                    pedersen_hash::Personalization::MerkleTree(i),
                    &preimage,
                    params,
                )?.get_x()
                .clone(); // Injective encoding

                auth_path_bits.push(cur_is_right);
            }

            // allocate input for is_right auth_path
            multipack::pack_into_inputs(cs.namespace(|| "packed auth_path"), &auth_path_bits)?;

            {
                // Validate that the root of the merkle tree that we calculated is the same as the input.

                // cur  * 1 = rt
                // enforce cur and rt are equal
                cs.enforce(
                    || "enforce root is correct",
                    |lc| lc + cur.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + rt.get_variable(),
                );
            }
        }

        // Expose the root
        rt.inputize(cs.namespace(|| "root"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use drgraph::{new_seed, BucketGraph, Graph};
    use fr32::{bytes_into_fr, fr_into_bytes};
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
            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph = BucketGraph::new(leaves, 6, new_seed());
            let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

            let pub_inputs: Vec<_> = (0..leaves)
                .map(|i| merklepor::PublicInputs {
                    challenge: i,
                    commitment: tree.root(),
                }).collect();
            let priv_inputs: Vec<_> = (0..leaves)
                .map(|i| merklepor::PrivateInputs {
                    tree: &tree,
                    leaf: bytes_into_fr::<Bls12>(
                        data_at_node(data.as_slice(), pub_inputs[i].challenge, pub_params.lambda)
                            .unwrap(),
                    ).unwrap(),
                }).collect();

            let proofs: Vec<_> = (0..leaves)
                .map(|i| {
                    merklepor::MerklePoR::prove(&pub_params, &pub_inputs[i], &priv_inputs[i])
                        .unwrap()
                }).collect();

            for i in 0..leaves {
                // make sure it verifies
                assert!(
                    merklepor::MerklePoR::verify(&pub_params, &pub_inputs[i], &proofs[i]).unwrap(),
                    "failed to verify merklepor proof"
                );
            }

            let auth_paths: Vec<_> = proofs.iter().map(|p| p.proof.as_options()).collect();
            let values: Vec<_> = proofs.iter().map(|p| Some(p.data)).collect();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let instance = ParallelProofOfRetrievability {
                params,
                values: values,
                auth_paths: auth_paths,
                root: Some(tree.root().into()),
            };

            instance
                .synthesize(&mut cs)
                .expect("failed to synthesize circuit");

            assert!(cs.is_satisfied(), "constraints not satisfied");

            assert_eq!(cs.num_inputs(), 34, "wrong number of inputs");
            assert_eq!(cs.num_constraints(), 99649, "wrong number of constraints");
            assert_eq!(cs.get_input(0, "ONE"), Fr::one());
        }
    }
}
