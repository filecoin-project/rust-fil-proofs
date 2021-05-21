use bellperson::gadgets::num;
use bellperson::{bls::Engine, ConstraintSystem, SynthesisError};

use crate::gadgets::constraint;

pub fn encode<E, CS>(
    mut cs: CS,
    key: &num::AllocatedNum<E>,
    value: &num::AllocatedNum<E>,
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    constraint::add(cs.namespace(|| "encode_add"), key, value)
}

pub fn decode<E, CS>(
    mut cs: CS,
    key: &num::AllocatedNum<E>,
    value: &num::AllocatedNum<E>,
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    constraint::sub(cs.namespace(|| "decode_sub"), value, key)
}
