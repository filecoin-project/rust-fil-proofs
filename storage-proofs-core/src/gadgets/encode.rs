use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

use crate::gadgets::constraint;

pub fn encode<Scalar, CS>(
    mut cs: CS,
    key: &AllocatedNum<Scalar>,
    value: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    constraint::add(cs.namespace(|| "encode_add"), key, value)
}

pub fn decode<Scalar, CS>(
    mut cs: CS,
    key: &AllocatedNum<Scalar>,
    value: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    constraint::sub(cs.namespace(|| "decode_sub"), value, key)
}
