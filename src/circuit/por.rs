use bellman::{ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::{boolean, num, pedersen_hash};
use sapling_crypto::jubjub::JubjubEngine;

use util::bytes_into_boolean_vec;

/// Create a proof of retrievability.
///
/// # Arguments
///
/// * `params` - The params for the bls curve.
/// * `value_commitment` - The value of the leaf.
/// * `value_commitment_size` - The size of the leaf.
/// * `auth_path` - The authentication path of the leaf in the tree.
/// * `root` - The merkle root of the tree.
pub fn proof_of_retrievability<E, CS>(
    cs: &mut CS,
    params: &E::Params,
    value_commitment: Option<&[u8]>,
    value_commitment_size: usize,
    auth_path: Vec<Option<(E::Fr, bool)>>,
    root: Option<E::Fr>,
) -> Result<(), SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let value_bits = bytes_into_boolean_vec(
        cs.namespace(|| "value into bits"),
        value_commitment,
        value_commitment_size,
    )?;

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
    use drgraph::{self, proof_into_options};
    use pairing::bls12_381::*;
    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::jubjub::JubjubBls12;
    use util::data_at_node;

    #[test]
    fn test_por_input_circuit_with_bls12_381() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaf_count = 6;
        let leaf_size = 32;

        for i in 0..6 {
            let data: Vec<u8> = (0..leaf_count * leaf_size).map(|_| rng.gen()).collect();

            let graph = drgraph::Graph::new(leaf_count, Some(drgraph::Sampling::Bucket(3)));
            let tree = graph.merkle_tree(data.as_slice(), leaf_size).unwrap();
            let merkle_proof = tree.gen_proof(i);
            let auth_path = proof_into_options(merkle_proof);
            let value_commitment = data_at_node(data.as_slice(), i + 1, leaf_size).unwrap();

            let root = tree.root();

            let mut cs = TestConstraintSystem::<Bls12>::new();

            proof_of_retrievability(
                &mut cs,
                params,
                Some(value_commitment),
                leaf_size * 8,
                auth_path.clone(),
                Some(root.into()),
            ).unwrap();

            assert_eq!(cs.num_inputs(), 2, "wrong number of inputs");
            assert_eq!(cs.num_constraints(), 4845, "wrong number of constraints");
            assert_eq!(cs.get_input(0, "ONE"), Fr::one(), "wrong input 0");
            assert_eq!(
                cs.get_input(1, "root/input variable"),
                root.into(),
                "wrong input 1"
            );

            assert!(cs.is_satisfied(), "constraints are not all satisfied");
        }
    }
}
