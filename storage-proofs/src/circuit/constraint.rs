use bellperson::{ConstraintSystem, SynthesisError};
use ff::Field;
use fil_sapling_crypto::circuit::num;
use paired::Engine;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::test::TestConstraintSystem;
    use paired::bls12_381::Bls12;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn sub_constraint() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a = num::AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(rng.gen())).unwrap();
            let b = num::AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(rng.gen())).unwrap();

            let res = sub(cs.namespace(|| "a-b"), &a, &b).expect("subtraction failed");

            let mut tmp = a.get_value().unwrap().clone();
            tmp.sub_assign(&b.get_value().unwrap());

            assert_eq!(res.get_value().unwrap(), tmp);
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn add_constraint() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a = num::AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(rng.gen())).unwrap();
            let b = num::AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(rng.gen())).unwrap();

            let res = add(cs.namespace(|| "a+b"), &a, &b).expect("add failed");

            let mut tmp = a.get_value().unwrap().clone();
            tmp.add_assign(&b.get_value().unwrap());

            assert_eq!(res.get_value().unwrap(), tmp);
            assert!(cs.is_satisfied());
        }
    }
}
