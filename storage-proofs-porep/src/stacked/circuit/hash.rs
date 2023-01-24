use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;
use filecoin_hashers::get_poseidon_constants;
use generic_array::typenum::{U11, U2};
use neptune::circuit::poseidon_hash;

/// Hash a list of bits.
pub fn hash_single_column<F, CS>(
    cs: CS,
    column: &[AllocatedNum<F>],
) -> Result<AllocatedNum<F>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    match column.len() {
        2 => {
            let consts = get_poseidon_constants::<F, U2>();
            poseidon_hash::<CS, F, U2>(cs, column.to_vec(), consts)
        }
        11 => {
            let consts = get_poseidon_constants::<F, U11>();
            poseidon_hash::<CS, F, U11>(cs, column.to_vec(), consts)
        }
        _ => panic!("unsupported column size: {}", column.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use ff::Field;
    use filecoin_hashers::{poseidon::PoseidonHasher, HashFunction, Hasher, R1CSHasher};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::TEST_SEED;

    use crate::stacked::vanilla::hash::hash_single_column as vanilla_hash_single_column;

    #[test]
    fn test_hash2_circuit() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        for _ in 0..10 {
            let mut cs = TestConstraintSystem::<Fr>::new();

            let a = Fr::random(&mut rng);
            let b = Fr::random(&mut rng);

            let a_num = {
                let mut cs = cs.namespace(|| "a");
                AllocatedNum::alloc(&mut cs, || Ok(a)).expect("alloc failed")
            };

            let b_num = {
                let mut cs = cs.namespace(|| "b");
                AllocatedNum::alloc(&mut cs, || Ok(b)).expect("alloc failed")
            };

            let out = PoseidonHasher::<Fr>::hash2_circuit(cs.namespace(|| "hash2"), &a_num, &b_num)
                .expect("hash2 function failed");

            assert!(cs.is_satisfied(), "constraints not satisfied");
            assert_eq!(cs.num_constraints(), 311);

            let expected: Fr =
                <PoseidonHasher<Fr> as Hasher>::Function::hash2(&a.into(), &b.into()).into();

            assert_eq!(
                expected,
                out.get_value().expect("get_value failed"),
                "circuit and non circuit do not match"
            );
        }
    }

    #[test]
    fn test_hash_single_column_circuit() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        for _ in 0..1 {
            let mut cs = TestConstraintSystem::<Fr>::new();

            let vals = vec![Fr::random(&mut rng); 11];
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
