use std::fmt::{self, Debug, Formatter};

use bellperson::{gadgets::num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

use crate::error::Result;

/// Root represents a root commitment which may be either a raw value or an already-allocated number.
/// This allows subcomponents to depend on roots which may optionally be shared with their parent
/// or sibling components.
#[derive(Clone)]
pub enum Root<Scalar: PrimeField> {
    Var(AllocatedNum<Scalar>),
    Val(Option<Scalar>),
}

impl<Scalar: PrimeField> Debug for Root<Scalar> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Root::Var(num) => write!(f, "Root::Var({:?})", num.get_value()),
            Root::Val(val) => write!(f, "Root::Val({:?})", val),
        }
    }
}

impl<Scalar: PrimeField> Root<Scalar> {
    pub fn from_allocated<CS: ConstraintSystem<Scalar>>(allocated: AllocatedNum<Scalar>) -> Self {
        Root::Var(allocated)
    }

    pub fn allocated<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: CS,
    ) -> Result<AllocatedNum<Scalar>, SynthesisError> {
        match self {
            Root::Var(allocated) => Ok(allocated.clone()),
            Root::Val(fr) => {
                AllocatedNum::alloc(cs, || fr.ok_or_else(|| SynthesisError::AssignmentMissing))
            }
        }
    }

    pub fn var<CS: ConstraintSystem<Scalar>>(cs: CS, fr: Scalar) -> Result<Self> {
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
