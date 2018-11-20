use bellman::{ConstraintSystem, SynthesisError};

use pairing::Engine;
use sapling_crypto::circuit::num::AllocatedNum;

#[derive(Clone)]
pub enum Root<E: Engine> {
    Var(AllocatedNum<E>),
    Val(E::Fr),
}

impl<E: Engine> Root<E> {
    pub fn allocated<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
    ) -> Result<AllocatedNum<E>, SynthesisError> {
        match self {
            Root::Var(allocated) => Ok(allocated.clone()),
            Root::Val(fr) => AllocatedNum::alloc(cs, || Ok(*fr)),
        }
    }
}
