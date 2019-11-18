use bellperson::gadgets::{
    boolean::Boolean,
    sha256::sha256 as sha256_circuit,
    {multipack, num},
};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::PrimeField;
use fil_sapling_crypto::jubjub::JubjubEngine;

use crate::circuit::uint64;

/// Key derivation function.
pub fn create_label<E, CS>(
    mut cs: CS,
    id: &[Boolean],
    parents: Vec<Vec<Boolean>>,
    window_index: Option<uint64::UInt64>,
    node: Option<uint64::UInt64>,
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    trace!("circuit: create_label");
    // ciphertexts will become a buffer of the layout
    // id | node | encodedParentNode1 | encodedParentNode1 | ...

    let mut ciphertexts = id.to_vec();

    if let Some(window_index) = window_index {
        ciphertexts.extend_from_slice(&window_index.to_bits_be());
    }

    if let Some(node) = node {
        ciphertexts.extend_from_slice(&node.to_bits_be());
    }

    for parent in parents.into_iter() {
        ciphertexts.extend_from_slice(&parent);
    }

    trace!("circuit: create_label: sha256");
    let alloc_bits = sha256_circuit(cs.namespace(|| "hash"), &ciphertexts[..])?;
    let fr = if alloc_bits[0].get_value().is_some() {
        let be_bits = alloc_bits
            .iter()
            .map(|v| v.get_value().unwrap())
            .collect::<Vec<bool>>();

        let le_bits = be_bits
            .chunks(8)
            .flat_map(|chunk| chunk.iter().rev())
            .copied()
            .take(E::Fr::CAPACITY as usize)
            .collect::<Vec<bool>>();

        Ok(multipack::compute_multipacking::<E>(&le_bits)[0])
    } else {
        Err(SynthesisError::AssignmentMissing)
    };

    num::AllocatedNum::<E>::alloc(cs.namespace(|| "result_num"), || fr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto;
    use crate::fr32::fr_into_bytes;
    use crate::util::bytes_into_boolean_vec_be;

    use bellperson::gadgets::boolean::Boolean;
    use bellperson::ConstraintSystem;
    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn create_label_circuit_no_node() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let m = 20;

        let id: Vec<u8> = fr_into_bytes::<Bls12>(&Fr::random(rng));
        let parents: Vec<Vec<u8>> = (0..m)
            .map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let id_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "id");
            bytes_into_boolean_vec_be(&mut cs, Some(id.as_slice()), id.len()).unwrap()
        };
        let parents_bits: Vec<Vec<Boolean>> = parents
            .clone()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut cs = cs.namespace(|| format!("parents {}", i));
                bytes_into_boolean_vec_be(&mut cs, Some(p.as_slice()), p.len()).unwrap()
            })
            .collect();
        let out = create_label(
            cs.namespace(|| "create_label"),
            &id_bits,
            parents_bits.clone(),
            None,
            None,
        )
        .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 292540);

        let input_bytes = parents.iter().fold(id, |mut acc, parent| {
            acc.extend(parent);
            acc
        });

        let expected = crypto::create_label::create_label(input_bytes.as_slice(), m);

        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    }
    #[test]
    fn create_label_circuit_with_node() {
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let m = 20;

        let id: Vec<u8> = fr_into_bytes::<Bls12>(&Fr::random(rng));
        let parents: Vec<Vec<u8>> = (0..m)
            .map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        let id_bits: Vec<Boolean> = {
            let mut cs = cs.namespace(|| "id");
            bytes_into_boolean_vec_be(&mut cs, Some(id.as_slice()), id.len()).unwrap()
        };
        let parents_bits: Vec<Vec<Boolean>> = parents
            .clone()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut cs = cs.namespace(|| format!("parents {}", i));
                bytes_into_boolean_vec_be(&mut cs, Some(p.as_slice()), p.len()).unwrap()
            })
            .collect();

        let window_index_raw = 12u64;
        let node_raw = 123456789u64;
        let window_index = uint64::UInt64::constant(window_index_raw);
        let node = uint64::UInt64::constant(node_raw);

        let out = create_label(
            cs.namespace(|| "create_label"),
            &id_bits,
            parents_bits.clone(),
            Some(window_index),
            Some(node),
        )
        .expect("key derivation function failed");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 292540);

        let mut input_bytes = id.to_vec();
        input_bytes.extend_from_slice(&window_index_raw.to_be_bytes());
        input_bytes.extend_from_slice(&node_raw.to_be_bytes());

        for parent in &parents {
            input_bytes.extend_from_slice(parent);
        }

        let expected = crypto::create_label::create_label(input_bytes.as_slice(), m);

        assert_eq!(
            expected,
            out.get_value().unwrap(),
            "circuit and non circuit do not match"
        );
    }
}
