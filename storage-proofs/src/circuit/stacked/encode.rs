use bellperson::{ConstraintSystem, SynthesisError};
use fil_sapling_crypto::circuit::num;
use paired::Engine;

use crate::circuit::constraint;

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
