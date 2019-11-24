use bellperson::gadgets::boolean::Boolean;
use bellperson::gadgets::num;
use bellperson::{ConstraintSystem, SynthesisError};
use ff::Field;
use fil_sapling_crypto::jubjub::JubjubEngine;

use crate::circuit::pedersen::{pedersen_compression_num as pedersen, pedersen_md_no_padding};
use crate::crypto::pedersen::PEDERSEN_BLOCK_SIZE;

/// Hash two elements together.
pub fn hash2<E, CS>(
    mut cs: CS,
    params: &E::Params,
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

    hash1(cs.namespace(|| "hash2"), params, &values)
}

/// Hash three elements together.
pub fn hash3<E, CS>(
    mut cs: CS,
    params: &E::Params,
    first: &[Boolean],
    second: &[Boolean],
    third: &[Boolean],
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

    values.extend_from_slice(third);
    // pad to full bytes
    while values.len() % 8 > 0 {
        values.push(Boolean::Constant(false));
    }

    hash1(cs.namespace(|| "hash3"), params, &values)
}

/// Hash a list of bits.
pub fn hash1<E, CS>(
    mut cs: CS,
    params: &E::Params,
    values: &[Boolean],
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    assert!(values.len() % 32 == 0, "input must be a multiple of 32bits");

    if values.is_empty() {
        // can happen with small layers
        num::AllocatedNum::alloc(cs.namespace(|| "hash1"), || Ok(E::Fr::zero()))
    } else if values.len() > PEDERSEN_BLOCK_SIZE {
        pedersen_md_no_padding(cs.namespace(|| "hash1"), params, values)
    } else {
        pedersen(cs.namespace(|| "hash1"), params, values)
    }
}

/// Hash a list of bits.
pub fn hash_single_column<E, CS>(
    mut cs: CS,
    params: &E::Params,
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
            row_num.to_bits_le(cs.namespace(|| format!("hash_single_column_row_{}_bits", i)))?;
        // pad to full bytes
        while row_bits.len() % 8 > 0 {
            row_bits.push(Boolean::Constant(false));
        }
        bits.extend(row_bits);
    }

    hash1(cs.namespace(|| "hash_single_column"), params, &bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::gadgets::boolean::Boolean;
    use bellperson::ConstraintSystem;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::fr32::fr_into_bytes;
    use crate::stacked::hash::hash2 as vanilla_hash2;
    use crate::util::bytes_into_boolean_vec;

    #[test]
    fn test_hash2_circuit() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..10 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a_bytes = fr_into_bytes::<Bls12>(&Fr::random(rng));
            let b_bytes = fr_into_bytes::<Bls12>(&Fr::random(rng));

            let a_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "a");
                bytes_into_boolean_vec(&mut cs, Some(a_bytes.as_slice()), a_bytes.len()).unwrap()
            };

            let b_bits: Vec<Boolean> = {
                let mut cs = cs.namespace(|| "b");
                bytes_into_boolean_vec(&mut cs, Some(b_bytes.as_slice()), b_bytes.len()).unwrap()
            };

            let out = hash2(cs.namespace(|| "hash2"), &JJ_PARAMS, &a_bits, &b_bits)
                .expect("hash2 function failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(cs.num_constraints(), 1376);

            let expected: Fr = vanilla_hash2(&a_bytes, &b_bytes).into();

            assert_eq!(
                expected,
                out.get_value().unwrap(),
                "circuit and non circuit do not match"
            );
        }
    }
}
