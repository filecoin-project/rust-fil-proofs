use bellman::{ConstraintSystem, SynthesisError};
use pairing::Field;
use sapling_crypto::circuit::{boolean, ecc, num, pedersen_hash};
use sapling_crypto::jubjub::{FixedGenerators, JubjubEngine};
use sapling_crypto::primitives::ValueCommitment;

/// create a proof of retrievability with the following inputs:
///
/// params - params for the bls curve
/// value_commitment - Pedersen commitment to the value
/// auth_path - The authentication path of the commitment in the tree
/// root - merkle root of the tree
pub fn proof_of_retrievability<E, CS>(
    cs: &mut CS,
    params: &E::Params,
    value_commitment: Option<ValueCommitment<E>>,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: Option<E::Fr>,
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let value_bits = {
        // Get the value in little-endian bit order
        let bits = expose_value_commitment(
            cs.namespace(|| "value commitment"),
            value_commitment,
            params,
        )?;

        // Compute the value's as a linear combination of the bits.
        let mut value_num: num::Num<E> = num::Num::zero();
        let mut coeff = E::Fr::one();
        for bit in &bits {
            value_num = value_num.add_bool_with_coeff(CS::one(), bit, coeff);
            coeff.double();
        }

        bits
    };

    assert_eq!(value_bits.len(), 64);

    // Compute the hash of the value
    let cm = pedersen_hash::pedersen_hash(
        cs.namespace(|| "note content hash"),
        pedersen_hash::Personalization::NoteCommitment,
        &value_bits,
        params,
    )?;

    // This is an injective encoding, as cur is a
    // point in the prime order subgroup.
    let mut cur = cm.get_x().clone();

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
    }

    {
        // Validate that the root of the merkle tree that we calculated is the same as the input.

        let real_root_value = root;

        // Allocate the "real" root that will be exposed.
        let rt = num::AllocatedNum::alloc(cs.namespace(|| "conditional root"), || {
            real_root_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // cur  * 1 = rt
        // enforce cur and rt are equal
        cs.enforce(
            || "conditionally enforce correct root",
            |lc| lc + cur.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + rt.get_variable(),
        );

        // Expose the root
        rt.inputize(cs.namespace(|| "root"))?;
    }

    Ok(())
}

/// Exposes a Pedersen commitment to the value as an input to the circuit.
pub fn expose_value_commitment<E, CS>(
    mut cs: CS,
    value_commitment: Option<ValueCommitment<E>>,
    params: &E::Params,
) -> Result<Vec<boolean::Boolean>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // Booleanize the value into little-endian bit order
    let value_bits = boolean::u64_into_boolean_vec_le(
        cs.namespace(|| "value"),
        value_commitment.as_ref().map(|c| c.value),
    )?;

    // Compute the value in the exponent
    let value = ecc::fixed_base_multiplication(
        cs.namespace(|| "compute the value in the exponent"),
        FixedGenerators::ValueCommitmentValue,
        &value_bits,
        params,
    )?;

    // Booleanize the randomness. This does not ensure
    // the bit representation is "in the field" because
    // it doesn't matter for security.
    let rcv = boolean::field_into_boolean_vec_le(
        cs.namespace(|| "rcv"),
        value_commitment.as_ref().map(|c| c.randomness),
    )?;

    // Compute the randomness in the exponent
    let rcv = ecc::fixed_base_multiplication(
        cs.namespace(|| "computation of rcv"),
        FixedGenerators::ValueCommitmentRandomness,
        &rcv,
        params,
    )?;

    // Compute the Pedersen commitment to the value
    let cv = value.add(cs.namespace(|| "computation of cv"), &rcv, params)?;

    // Expose the commitment as an input to the circuit
    cv.inputize(cs.namespace(|| "commitment point"))?;

    Ok(value_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::*;
    use drgraph::proof_into_options;
    use hasher::pedersen::merkle_tree_from_u64;
    use pairing::bls12_381::*;
    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;

    #[test]
    fn test_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaf_count = 32;

        for _ in 0..10 {
            let value_commitment = ValueCommitment {
                value: rng.gen(),
                randomness: rng.gen(),
            };

            let mut values: Vec<u64> = (0..leaf_count).map(|_| rng.gen()).collect();
            values.push(value_commitment.value);

            let tree = merkle_tree_from_u64(values);
            let merkle_proof = tree.gen_proof(leaf_count);
            // below we construct the auth_path, such that it matches the expecations
            // of our circuit
            let auth_path = proof_into_options(merkle_proof);

            let root = tree.root();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            proof_of_retrievability(
                &mut cs,
                params,
                Some(value_commitment.clone()),
                auth_path.clone(),
                Some(root.into()),
            ).unwrap();

            assert!(cs.is_satisfied());
            assert_eq!(cs.num_inputs(), 4);
            assert_eq!(cs.get_input(0, "ONE"), Fr::one());
            assert_eq!(cs.get_input(3, "root/input variable"), root.into());
        }
    }
}
