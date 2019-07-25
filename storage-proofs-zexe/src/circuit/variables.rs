use std::fmt;

use algebra::PairingEngine as Engine;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::fields::fp::FpGadget;
use snark_gadgets::utils::AllocGadget;

/// Root represents a root commitment which may be either a raw value or an already-allocated number.
/// This allows subcomponents to depend on roots which may optionally be shared with their parent
/// or sibling components.
#[derive(Clone)]
pub enum Root<E: Engine> {
    Var(FpGadget<E>),
    Val(Option<E::Fr>),
}

impl<E: Engine> fmt::Debug for Root<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Root::Var(num) => write!(f, "Root::Var({:?})", num.value),
            Root::Val(val) => write!(f, "Root::Val({:?})", val),
        }
    }
}

impl<E: Engine> Root<E> {
    pub fn allocated<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
    ) -> Result<FpGadget<E>, SynthesisError> {
        match self {
            Root::Var(allocated) => Ok(allocated.clone()),
            Root::Val(fr) => {
                FpGadget::alloc(cs, || fr.ok_or_else(|| SynthesisError::AssignmentMissing))
            }
        }
    }

    pub fn var<CS: ConstraintSystem<E>>(cs: CS, fr: E::Fr) -> Self {
        Root::Var(FpGadget::alloc(cs, || Ok(fr)).unwrap())
    }

    pub fn is_some(&self) -> bool {
        match self {
            Root::Var(_) => true,
            Root::Val(Some(_)) => true,
            Root::Val(None) => false,
        }
    }
}
