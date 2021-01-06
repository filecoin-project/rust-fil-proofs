use bellperson::{bls::Engine, gadgets::num, ConstraintSystem, SynthesisError};
use ff::Field;

/// Adds a constraint to CS, enforcing an equality relationship between the allocated numbers a and b.
///
/// a == b
pub fn equal<E: Engine, A, AR, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    annotation: A,
    a: &num::AllocatedNum<E>,
    b: &num::AllocatedNum<E>,
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
pub fn sum<E: Engine, A, AR, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    annotation: A,
    a: &num::AllocatedNum<E>,
    b: &num::AllocatedNum<E>,
    sum: &num::AllocatedNum<E>,
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

pub fn add<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    a: &num::AllocatedNum<E>,
    b: &num::AllocatedNum<E>,
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    let res = num::AllocatedNum::alloc(cs.namespace(|| "add_num"), || {
        let mut tmp = a
            .get_value()
            .ok_or_else(|| SynthesisError::AssignmentMissing)?;
        tmp.add_assign(
            &b.get_value()
                .ok_or_else(|| SynthesisError::AssignmentMissing)?,
        );

        Ok(tmp)
    })?;

    // a + b = res
    sum(&mut cs, || "sum constraint", &a, &b, &res);

    Ok(res)
}

pub fn sub<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    a: &num::AllocatedNum<E>,
    b: &num::AllocatedNum<E>,
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    let res = num::AllocatedNum::alloc(cs.namespace(|| "sub_num"), || {
        let mut tmp = a
            .get_value()
            .ok_or_else(|| SynthesisError::AssignmentMissing)?;
        tmp.sub_assign(
            &b.get_value()
                .ok_or_else(|| SynthesisError::AssignmentMissing)?,
        );

        Ok(tmp)
    })?;

    // a - b = res
    difference(&mut cs, || "subtraction constraint", &a, &b, &res);

    Ok(res)
}

/// Adds a constraint to CS, enforcing a difference relationship between the allocated numbers a, b, and difference.
///
/// a - b = difference
pub fn difference<E: Engine, A, AR, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    annotation: A,
    a: &num::AllocatedNum<E>,
    b: &num::AllocatedNum<E>,
    difference: &num::AllocatedNum<E>,
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

    use bellperson::bls::{Bls12, Fr};
    use bellperson::util_cs::test_cs::TestConstraintSystem;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn add_constraint() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a = num::AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(Fr::random(rng))).unwrap();
            let b = num::AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(Fr::random(rng))).unwrap();

            let res = add(cs.namespace(|| "a+b"), &a, &b).expect("add failed");

            let mut tmp = a.get_value().unwrap();
            tmp.add_assign(&b.get_value().unwrap());

            assert_eq!(res.get_value().unwrap(), tmp);
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn sub_constraint() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a = num::AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(Fr::random(rng))).unwrap();
            let b = num::AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(Fr::random(rng))).unwrap();

            let res = sub(cs.namespace(|| "a-b"), &a, &b).expect("subtraction failed");

            let mut tmp = a.get_value().unwrap();
            tmp.sub_assign(&b.get_value().unwrap());

            assert_eq!(res.get_value().unwrap(), tmp);
            assert!(cs.is_satisfied());
        }
    }
}
