use bellperson::gadgets::num;
use bellperson::{ConstraintSystem, SynthesisError};
use generic_array::typenum;
use neptune::circuit::poseidon_hash;
use paired::bls12_381::{Bls12, Fr};

/// Hash a list of bits.
pub fn hash_single_column<CS>(
    mut cs: CS,
    column: &[Option<Fr>],
) -> Result<num::AllocatedNum<Bls12>, SynthesisError>
where
    CS: ConstraintSystem<Bls12>,
{
    let column = column
        .iter()
        .enumerate()
        .map(|(i, val)| {
            num::AllocatedNum::alloc(cs.namespace(|| format!("hash_num_row_{}", i)), || {
                val.ok_or_else(|| SynthesisError::AssignmentMissing)
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    match column.len() {
        1 => poseidon_hash::<CS, Bls12, typenum::U1>(
            cs,
            column,
            &*crate::hasher::types::POSEIDON_CONSTANTS_1,
        ),
        2 => poseidon_hash::<CS, Bls12, typenum::U2>(
            cs,
            column,
            &*crate::hasher::types::POSEIDON_CONSTANTS_2,
        ),
        11 => poseidon_hash::<CS, Bls12, typenum::U11>(
            cs,
            column,
            &*crate::hasher::types::POSEIDON_CONSTANTS_11,
        ),
        _ => panic!("unsupported column size: {}", column.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::ConstraintSystem;
    use ff::Field;
    use paired::bls12_381::{Bls12, Fr};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::crypto::pedersen::JJ_PARAMS;
    use crate::gadgets::TestConstraintSystem;
    use crate::hasher::{HashFunction, Hasher, PedersenHasher};
    use crate::porep::stacked::vanilla::hash::hash_single_column as vanilla_hash_single_column;

    #[test]
    fn test_hash2_circuit() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..10 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a = Fr::random(rng);
            let b = Fr::random(rng);

            let a_num = {
                let mut cs = cs.namespace(|| "a");
                num::AllocatedNum::alloc(&mut cs, || Ok(a)).unwrap()
            };

            let b_num = {
                let mut cs = cs.namespace(|| "b");
                num::AllocatedNum::alloc(&mut cs, || Ok(b)).unwrap()
            };

            let out = <PedersenHasher as Hasher>::Function::hash2_circuit(
                cs.namespace(|| "hash2"),
                &a_num,
                &b_num,
                &JJ_PARAMS,
            )
            .expect("hash2 function failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(cs.num_constraints(), 1_371);

            let expected: Fr =
                <PedersenHasher as Hasher>::Function::hash2(&a.into(), &b.into()).into();

            assert_eq!(
                expected,
                out.get_value().unwrap(),
                "circuit and non circuit do not match"
            );
        }
    }

    #[test]
    fn test_hash_single_column_circuit() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..1 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let vals = vec![Fr::random(rng); 11];
            let vals_opt = vals.iter().map(|v| Some(*v)).collect::<Vec<_>>();

            let out = hash_single_column(cs.namespace(|| "hash_single_column"), &vals_opt)
                .expect("hash_single_column function failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(cs.num_constraints(), 601);

            let expected: Fr = vanilla_hash_single_column(&vals).into();

            assert_eq!(
                expected,
                out.get_value().unwrap(),
                "circuit and non circuit do not match"
            );
        }
    }
}
