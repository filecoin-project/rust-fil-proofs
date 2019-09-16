use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::blake2s::blake2s as blake2s_circuit;
use fil_sapling_crypto::circuit::boolean::Boolean;
use fil_sapling_crypto::circuit::{multipack, num};
use fil_sapling_crypto::jubjub::JubjubEngine;

/// Hash two elements together.
pub fn hash2<E, CS>(
    mut cs: CS,
    first: &[Boolean],
    second: &[Boolean],
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let mut values = Vec::new();
    values.extend_from_slice(first);

    // pad to full bytes
    while values.len() % 8 > 0 {
        values.push(Boolean::Constant(false));
    }

    values.extend_from_slice(second);
    // pad to full bytes
    while values.len() % 8 > 0 {
        values.push(Boolean::Constant(false));
    }

    hash1(cs.namespace(|| "hash2"), &values)
}

/// Hash a list of bits.
pub fn hash1<E, CS>(mut cs: CS, values: &[Boolean]) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let personalization = vec![0u8; 8];

    let hash_bits = blake2s_circuit(cs.namespace(|| "hash1"), &values, &personalization)?;

    let hash_fr = match hash_bits[0].get_value() {
        Some(_) => {
            let bits = hash_bits
                .iter()
                .map(|v| v.get_value().unwrap())
                .collect::<Vec<bool>>();
            let frs = multipack::compute_multipacking::<E>(&bits);
            Ok(frs[0])
        }
        None => Err(SynthesisError::AssignmentMissing),
    };

    num::AllocatedNum::alloc(cs.namespace(|| "hash1_num"), || hash_fr)
}

/// Hash a list of bits.
pub fn hash_single_column<E, CS>(
    mut cs: CS,
    rows: &[Option<E::Fr>],
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    let mut bits = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let row_num = num::AllocatedNum::alloc(
            cs.namespace(|| format!("hash_single_column_row_{}_num", i)),
            || {
                row.map(Into::into)
                    .ok_or_else(|| SynthesisError::AssignmentMissing)
            },
        )?;
        let mut row_bits =
            row_num.into_bits_le(cs.namespace(|| format!("hash_single_column_row_{}_bits", i)))?;
        // pad to full bytes
        while row_bits.len() % 8 > 0 {
            row_bits.push(Boolean::Constant(false));
        }
        bits.extend(row_bits);
    }

    hash1(cs.namespace(|| "hash_single_column"), &bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::ConstraintSystem;
    use fil_sapling_crypto::circuit::boolean::Boolean;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    use crate::circuit::test::TestConstraintSystem;
    use crate::fr32::fr_into_bytes;
    use crate::util::bytes_into_boolean_vec;

    use crate::zigzag::hash::hash2 as vanilla_hash2;

    #[test]
    fn test_hash2_circuit() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..10 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a_bytes = fr_into_bytes::<Bls12>(&rng.gen());
            let b_bytes = fr_into_bytes::<Bls12>(&rng.gen());

            let a_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "a");
                bytes_into_boolean_vec(&mut cs, Some(a_bytes.as_slice()), a_bytes.len()).unwrap()
            };

            let b_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "b");
                bytes_into_boolean_vec(&mut cs, Some(b_bytes.as_slice()), b_bytes.len()).unwrap()
            };

            let out =
                hash2(cs.namespace(|| "hash2"), &a_bits, &b_bits).expect("hash2 function failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(cs.num_constraints(), 21518);

            let expected = vanilla_hash2(&a_bytes, &b_bytes);

            assert_eq!(
                expected,
                fr_into_bytes::<Bls12>(&out.get_value().unwrap()),
                "circuit and non circuit do not match"
            );
        }
    }
}
