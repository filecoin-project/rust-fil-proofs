pub use halo2_gadgets::utilities::ternary;

use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

// Returns `a` if `bit` is set, otherwise returns `b`.
//
// Assumes `bit` is already boolean constrained.
#[inline]
pub fn pick<F: FieldExt>(bit: Expression<F>, a: Expression<F>, b: Expression<F>) -> Expression<F> {
    ternary(bit, a, b)
}
