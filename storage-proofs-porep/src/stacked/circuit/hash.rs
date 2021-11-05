use bellperson::{bls::Bls12, gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use filecoin_hashers::{POSEIDON_CONSTANTS_11, POSEIDON_CONSTANTS_2};
use generic_array::typenum::{U11, U2};
use neptune::circuit::poseidon_hash;

/// Hash a list of bits.
pub fn hash_single_column<CS>(
    cs: CS,
    column: &[AllocatedNum<Bls12>],
) -> Result<AllocatedNum<Bls12>, SynthesisError>
where
    CS: ConstraintSystem<Bls12>,
{
    match column.len() {
        2 => poseidon_hash::<CS, Bls12, U2>(cs, column.to_vec(), &*POSEIDON_CONSTANTS_2),
        11 => poseidon_hash::<CS, Bls12, U11>(cs, column.to_vec(), &*POSEIDON_CONSTANTS_11),
        _ => panic!("unsupported column size: {}", column.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::{bls::Fr, util_cs::test_cs::TestConstraintSystem};
    use ff::Field;
    use filecoin_hashers::{poseidon::PoseidonHasher, HashFunction, Hasher};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::TEST_SEED;

    use crate::stacked::vanilla::hash::hash_single_column as vanilla_hash_single_column;

    #[test]
    fn test_hash2_circuit() {
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        for _ in 0..10 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a = Fr::random(rng);
            let b = Fr::random(rng);

            let a_num = {
                let mut cs = cs.namespace(|| "a");
                AllocatedNum::alloc(&mut cs, || Ok(a)).expect("alloc failed")
            };

            let b_num = {
                let mut cs = cs.namespace(|| "b");
                AllocatedNum::alloc(&mut cs, || Ok(b)).expect("alloc failed")
            };

            let out = <PoseidonHasher as Hasher>::Function::hash2_circuit(
                cs.namespace(|| "hash2"),
                &a_num,
                &b_num,
            )
            .expect("hash2 function failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(cs.num_constraints(), 311);

            let expected: Fr =
                <PoseidonHasher as Hasher>::Function::hash2(&a.into(), &b.into()).into();

            assert_eq!(
                expected,
                out.get_value().expect("get_value failed"),
                "circuit and non circuit do not match"
            );
        }
    }

    #[test]
    fn test_hash_single_column_circuit() {
        let rng = &mut XorShiftRng::from_seed(TEST_SEED);

        for _ in 0..1 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let vals = vec![Fr::random(rng); 11];
            let vals_opt = vals
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("num_{}", i)), || Ok(*v))
                        .expect("alloc failed")
                })
                .collect::<Vec<_>>();

            let out = hash_single_column(cs.namespace(|| "hash_single_column"), &vals_opt)
                .expect("hash_single_column function failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(cs.num_constraints(), 598);

            let expected: Fr = vanilla_hash_single_column(&vals);

            assert_eq!(
                expected,
                out.get_value().expect("get_value failed"),
                "circuit and non circuit do not match"
            );
        }
    }
}
