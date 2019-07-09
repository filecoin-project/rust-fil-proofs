use bellperson::ConstraintSystem;
use fil_sapling_crypto::circuit::boolean::AllocatedBit;
use fil_sapling_crypto::circuit::num::AllocatedNum;
use paired::Engine;

pub(super) fn alloc_priv_num<CS, E, T>(cs: &mut CS, annotation: &str, value: T) -> AllocatedNum<E>
where
    CS: ConstraintSystem<E>,
    E: Engine,
    T: Into<E::Fr>,
{
    let value: E::Fr = value.into();
    // Unwrapping here is safe because `AllocatedNum::alloc` will only return an `Err` if the
    // value being allocated fails to be converted into an `Fr`. Our `value` parameter has the bound
    // `Into<Fr>` which can't return an `Err`.
    AllocatedNum::alloc(cs.namespace(|| annotation), || Ok(value)).unwrap()
}

pub(super) fn alloc_priv_bit<CS, E>(cs: &mut CS, annotation: &str, value: bool) -> AllocatedBit
where
    CS: ConstraintSystem<E>,
    E: Engine,
{
    // Unwrapping here is safe because `AllocatedBit::alloc` will only return an `Err` if its value
    // argmuent is `None`. This function accepts a `bool` as its `value` as opposed to an
    // `Option<bool>`, therefore allocation will never fail.
    AllocatedBit::alloc(cs.namespace(|| annotation), Some(value)).unwrap()
}
