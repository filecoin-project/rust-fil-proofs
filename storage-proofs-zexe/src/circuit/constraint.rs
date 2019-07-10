use algebra::PairingEngine as Engine;
use snark::ConstraintSystem;
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::utils::EqGadget;
use snark_gadgets::fields::FieldGadget;

//use bellperson::ConstraintSystem;
//use fil_sapling_crypto::circuit::num;
//use paired::Engine;

/// Adds a constraint to CS, enforcing an equality relationship between the allocated numbers a and b.
///
/// a == b
pub fn equal<E: Engine, A, AR, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    annotation: A,
    a: &FpGadget<E>,
    b: &FpGadget<E>
//    a: &num::AllocatedNum<E>,
//    b: &num::AllocatedNum<E>,
) where
    A: FnOnce() -> AR,
    AR: Into<String>,
{
    // a * 1 = b

    a.enforce_equal(cs, b);

//    cs.enforce(
//        annotation,
//        |lc| lc + a.variable(),
//        |lc| lc + CS::one(),
//        |lc| lc + b.variable(),
//    );
}

/// Adds a constraint to CS, enforcing a difference relationship between the allocated numbers a, b, and difference.
///
/// a - b = difference
pub fn difference<E: Engine, A, AR, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    annotation: A,
    a: &FpGadget<E>,
    b: &FpGadget<E>,
    difference: &FpGadget<E>
//    a: &num::AllocatedNum<E>,
//    b: &num::AllocatedNum<E>,
//    difference: &num::AllocatedNum<E>,
) where
    A: FnOnce() -> AR,
    AR: Into<String>,
{

    let sum = b.add(cs.ns(|| "sum"), difference).unwrap();
    a.enforce_equal(cs, &sum);

    //    difference = a-b
    // => difference + b = a
    // => (difference + b) * 1 = a
//    cs.enforce(
//        annotation,
//        |lc| lc + difference.get_variable() + b.get_variable(),
//        |lc| lc + CS::one(),
//        |lc| lc + a.get_variable(),
//    );
}
