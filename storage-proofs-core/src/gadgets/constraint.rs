use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

/// Adds a constraint to CS, enforcing an equality relationship between the allocated numbers a and b.
///
/// a == b
pub fn equal<Scalar: PrimeField, A, AR, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    annotation: A,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
) where
    A: FnOnce() -> AR,
    AR: Into<String>,
{
    // a * 1 = b
    cs.enforce(
        annotation,
        |lc| lc + a.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + b.get_variable(),
    );
}

/// Adds a constraint to CS, enforcing a add relationship between the allocated numbers a, b, and sum.
///
/// a + b = sum
pub fn sum<Scalar: PrimeField, A, AR, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    annotation: A,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
    sum: &AllocatedNum<Scalar>,
) where
    A: FnOnce() -> AR,
    AR: Into<String>,
{
    // (a + b) * 1 = sum
    cs.enforce(
        annotation,
        |lc| lc + a.get_variable() + b.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + sum.get_variable(),
    );
}

pub fn add<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let res = AllocatedNum::alloc(cs.namespace(|| "add_num"), || {
        let mut tmp = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        tmp += &b.get_value().ok_or(SynthesisError::AssignmentMissing)?;

        Ok(tmp)
    })?;

    // a + b = res
    sum(&mut cs, || "sum constraint", &a, &b, &res);

    Ok(res)
}

pub fn sub<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let res = AllocatedNum::alloc(cs.namespace(|| "sub_num"), || {
        let mut tmp = a.get_value().ok_or(SynthesisError::AssignmentMissing)?;
        tmp -= &b.get_value().ok_or(SynthesisError::AssignmentMissing)?;

        Ok(tmp)
    })?;

    // a - b = res
    difference(&mut cs, || "subtraction constraint", &a, &b, &res);

    Ok(res)
}

/// Adds a constraint to CS, enforcing a difference relationship between the allocated numbers a, b, and difference.
///
/// a - b = difference
pub fn difference<Scalar: PrimeField, A, AR, CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    annotation: A,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
    difference: &AllocatedNum<Scalar>,
) where
    A: FnOnce() -> AR,
    AR: Into<String>,
{
    //    difference = a-b
    // => difference + b = a
    // => (difference + b) * 1 = a
    cs.enforce(
        annotation,
        |lc| lc + difference.get_variable() + b.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + a.get_variable(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use ff::Field;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::TEST_SEED;

    #[test]
    fn add_constraint() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Fr>::new();

            let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(Fr::random(&mut rng)))
                .expect("alloc failed");
            let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(Fr::random(&mut rng)))
                .expect("alloc failed");

            let res = add(cs.namespace(|| "a+b"), &a, &b).expect("add failed");

            let mut tmp = a.get_value().expect("get_value failed");
            tmp += &b.get_value().expect("get_value failed");

            assert_eq!(res.get_value().expect("get_value failed"), tmp);
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn sub_constraint() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Fr>::new();

            let a = AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(Fr::random(&mut rng)))
                .expect("alloc failed");
            let b = AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(Fr::random(&mut rng)))
                .expect("alloc failed");

            let res = sub(cs.namespace(|| "a-b"), &a, &b).expect("subtraction failed");

            let mut tmp = a.get_value().expect("get_value failed");
            tmp -= &b.get_value().expect("get_value failed");

            assert_eq!(res.get_value().expect("get_value failed"), tmp);
            assert!(cs.is_satisfied());
        }
    }
}
