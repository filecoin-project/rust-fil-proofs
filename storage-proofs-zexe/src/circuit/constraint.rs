use algebra::PairingEngine as Engine;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::fields::FieldGadget;
use snark_gadgets::utils::EqGadget;

/// Adds a constraint to CS, enforcing an equality relationship between the allocated numbers a and b.
///
/// a == b
pub fn equal<E: Engine, A, AR, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    _annotation: A,
    a: &FpGadget<E>,
    b: &FpGadget<E>,
) -> Result<(), SynthesisError>
where
    A: FnOnce() -> AR,
    AR: Into<String>,
{
    // a * 1 = b

    a.enforce_equal(cs, b)
}

/// Adds a constraint to CS, enforcing a difference relationship between the allocated numbers a, b, and difference.
///
/// a - b = difference
pub fn difference<E: Engine, A, AR, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    _annotation: A,
    a: &FpGadget<E>,
    b: &FpGadget<E>,
    difference: &FpGadget<E>,
) -> Result<(), SynthesisError>
where
    A: FnOnce() -> AR,
    AR: Into<String>,
{
    //    difference = a-b
    // => difference + b = a
    // => (difference + b) * 1 = a
    let sum = b.add(cs.ns(|| "sum"), difference)?;
    a.enforce_equal(cs, &sum)
}
