use algebra::PairingEngine as Engine;
use snark::ConstraintSystem;
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::utils::EqGadget;
use snark_gadgets::fields::FieldGadget;

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
) where
    A: FnOnce() -> AR,
    AR: Into<String>,
{

    //    difference = a-b
    // => difference + b = a
    // => (difference + b) * 1 = a
    let sum = b.add(cs.ns(|| "sum"), difference).unwrap();
    a.enforce_equal(cs, &sum);

}
