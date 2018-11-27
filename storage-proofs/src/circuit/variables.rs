use bellman::{ConstraintSystem, SynthesisError};

use pairing::Engine;
use sapling_crypto::circuit::num::AllocatedNum;

/// Root represents a root commitment which may be either a raw value or an already-allocated number.
/// This allows subcomponents to depend on roots which may optionally be shared with their parent
/// or sibling components.
#[derive(Clone)]
pub enum Root<E: Engine> {
    Var(AllocatedNum<E>),
    Val(Option<E::Fr>),
}

impl<E: Engine> Root<E> {
    pub fn allocated<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
    ) -> Result<AllocatedNum<E>, SynthesisError> {
        match self {
            Root::Var(allocated) => Ok(allocated.clone()),
            Root::Val(Some(fr)) => AllocatedNum::alloc(cs, || Ok(*fr)),
            Root::Val(None) => Err(SynthesisError::AssignmentMissing),
        }
    }

    pub fn var<CS: ConstraintSystem<E>>(cs: CS, fr: E::Fr) -> Self {
        Root::Var(AllocatedNum::alloc(cs, || Ok(fr)).unwrap())
    }
}
