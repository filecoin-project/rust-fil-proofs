use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::{boolean, multipack, num, pedersen_hash};
use sapling_crypto::jubjub::JubjubEngine;

/// Create a proof of retrievability.
///
/// # Arguments
///
/// * `params` - The params for the bls curve.
/// * `value` - The value of the leaf.
/// * `lambda` - The size of the leaf in bits.
/// * `auth_path` - The authentication path of the leaf in the tree.
/// * `root` - The merkle root of the tree.
///
/// # Public Inputs
///
/// This circuit expects the following public inputs.
///
/// * [0] - packed version of `value` as bits. (might be more than one Fr)
/// * [1] - packed version of the `is_right` components of the auth_path.
/// * [2] - the merkle root of the tree.
///
/// Note: All public inputs must be provided as `E::Fr`.
pub fn proof_of_retrievability<E, CS>(
    mut cs: CS,
    params: &E::Params,
    value: Option<&E::Fr>,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: Option<E::Fr>,
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let value_num = num::AllocatedNum::alloc(cs.namespace(|| "value"), || {
        Ok(*value.ok_or_else(|| SynthesisError::AssignmentMissing)?)
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
        let path_element = num::AllocatedNum::alloc(cs.namespace(|| "path element"), || {
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

        let real_root_value = root;

        // Allocate the "real" root that will be exposed.
        let rt = num::AllocatedNum::alloc(cs.namespace(|| "root value"), || {
            real_root_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // cur  * 1 = rt
        // enforce cur and rt are equal
        cs.enforce(
            || "enforce root is correct",
            |lc| lc + cur.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + rt.get_variable(),
        );

        // Expose the root
        rt.inputize(cs.namespace(|| "root"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use drgraph;
    use fr32::{bytes_into_fr, fr_into_bytes};
    use merklepor;
    use pairing::bls12_381::*;
    use pairing::Field;
    use proof::ProofScheme;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::multipack;
    use sapling_crypto::jubjub::JubjubBls12;
    use util::data_at_node;

    #[test]
    fn test_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = 6;
        let lambda = 32;

        for i in 0..6 {
            // -- Basic Setup

            let data: Vec<u8> = (0..leaves)
                .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
                .collect();

            let graph = drgraph::Graph::new(leaves, Some(drgraph::Sampling::Bucket(16)));
            let tree = graph.merkle_tree(data.as_slice(), lambda).unwrap();

            // -- MerklePoR

            let pub_params = merklepor::PublicParams { lambda, leaves };
            let pub_inputs = merklepor::PublicInputs {
                challenge: i,
                commitment: tree.root(),
            };

            let priv_inputs = merklepor::PrivateInputs {
                tree: &tree,
                leaf: bytes_into_fr::<Bls12>(
                    data_at_node(data.as_slice(), pub_inputs.challenge + 1, pub_params.lambda)
                        .unwrap(),
                ).unwrap(),
            };

            // create a non circuit proof
            let proof =
                merklepor::MerklePoR::prove(&pub_params, &pub_inputs, &priv_inputs).unwrap();

            // make sure it verifies
            assert!(
                merklepor::MerklePoR::verify(&pub_params, &pub_inputs, &proof).unwrap(),
                "failed to verify merklepor proof"
            );

            // -- Circuit

            let mut cs = TestConstraintSystem::<Bls12>::new();

            proof_of_retrievability(
                cs.namespace(|| "por"),
                params,
                Some(&proof.data),
                proof.proof.as_options(),
                Some(pub_inputs.commitment.into()),
            ).unwrap();

            assert_eq!(cs.num_inputs(), 4, "wrong number of inputs");
            assert_eq!(cs.num_constraints(), 4847, "wrong number of constraints");

            let auth_path_bits: Vec<bool> = proof
                .proof
                .path()
                .iter()
                .map(|(_, is_right)| *is_right)
                .collect();
            let packed_auth_path = multipack::compute_multipacking::<Bls12>(&auth_path_bits);

            let mut expected_inputs = vec![proof.data];
            expected_inputs.extend(packed_auth_path);
            expected_inputs.push(pub_inputs.commitment.into());

            assert_eq!(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");

            assert_eq!(
                cs.get_input(1, "por/value num/input variable"),
                expected_inputs[0],
                "wrong data"
            );

            assert_eq!(
                cs.get_input(2, "por/packed auth_path/input 0"),
                expected_inputs[1],
                "wrong packed_auth_path"
            );

            assert_eq!(
                cs.get_input(3, "por/root/input variable"),
                expected_inputs[2],
                "wrong root input"
            );

            assert!(cs.is_satisfied(), "constraints are not all satisfied");
            assert!(cs.verify(&expected_inputs), "failed to verify inputs");
        }
    }
}
