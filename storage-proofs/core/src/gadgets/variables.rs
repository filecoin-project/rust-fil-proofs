use std::fmt;

use anyhow::Result;

use bellperson::gadgets::num::AllocatedNum;
use bellperson::{bls::Engine, ConstraintSystem, SynthesisError};

/// Root represents a root commitment which may be either a raw value or an already-allocated number.
/// This allows subcomponents to depend on roots which may optionally be shared with their parent
/// or sibling components.
#[derive(Clone)]
pub enum Root<E: Engine> {
    Var(AllocatedNum<E>),
    Val(Option<E::Fr>),
}

impl<E: Engine> fmt::Debug for Root<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Root::Var(num) => write!(f, "Root::Var({:?})", num.get_value()),
            Root::Val(val) => write!(f, "Root::Val({:?})", val),
        }
    }
}

impl<E: Engine> Root<E> {
    pub fn from_allocated<CS: ConstraintSystem<E>>(allocated: AllocatedNum<E>) -> Self {
        Root::Var(allocated)
    }

    pub fn allocated<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
    ) -> Result<AllocatedNum<E>, SynthesisError> {
        match self {
            Root::Var(allocated) => Ok(allocated.clone()),
            Root::Val(fr) => {
                AllocatedNum::alloc(cs, || fr.ok_or_else(|| SynthesisError::AssignmentMissing))
            }
        }
    }

    pub fn var<CS: ConstraintSystem<E>>(cs: CS, fr: E::Fr) -> Result<Self> {
        Ok(Root::Var(AllocatedNum::alloc(cs, || Ok(fr))?))
    }

    pub fn is_some(&self) -> bool {
        match self {
            Root::Var(_) => true,
            Root::Val(Some(_)) => true,
            Root::Val(None) => false,
        }
    }
}
