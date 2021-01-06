use bellperson::gadgets::{
    boolean::Boolean,
    num::{AllocatedNum, Num},
};
use bellperson::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, ScalarEngine};

/// Takes a sequence of booleans and exposes them as a single compact Num.
pub fn pack_bits<E, CS>(mut cs: CS, bits: &[Boolean]) -> Result<AllocatedNum<E>, SynthesisError>
where
    E: ScalarEngine,
    CS: ConstraintSystem<E>,
{
    let mut num = Num::<E>::zero();
    let mut coeff = E::Fr::one();
    for bit in bits.iter().take(E::Fr::CAPACITY as usize) {
        num = num.add_bool_with_coeff(CS::one(), &bit, coeff);

        coeff.double();
    }

    let alloc_num = AllocatedNum::alloc(cs.namespace(|| "input"), || {
        num.get_value()
            .ok_or_else(|| SynthesisError::AssignmentMissing)
    })?;

    // num * 1 = input
    cs.enforce(
        || "packing constraint",
        |_| num.lc(E::Fr::one()),
        |lc| lc + CS::one(),
        |lc| lc + alloc_num.get_variable(),
    );

    Ok(alloc_num)
}
