pub mod boolean;
pub mod sha256;
pub mod uint32;

use std::cmp::max;

use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Fixed},
};

#[cfg(test)]
pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];

type AdviceEq = Vec<Column<Advice>>;
type AdviceNeq = Vec<Column<Advice>>;
type FixedEq = Vec<Column<Fixed>>;
type FixedNeq = Vec<Column<Fixed>>;

#[derive(Clone, Copy, Default)]
pub struct NumCols {
    pub advice_eq: usize,
    pub advice_neq: usize,
    pub fixed_eq: usize,
    pub fixed_neq: usize,
}

impl NumCols {
    pub fn for_circuit(chips: &[NumCols]) -> Self {
        let mut advice_total = 0;
        let mut fixed_total = 0;
        let mut advice_eq = 0;
        let mut fixed_eq = 0;

        for chip in chips {
            advice_total = max(chip.advice_eq + chip.advice_neq, advice_total);
            fixed_total = max(chip.fixed_eq + chip.fixed_neq, fixed_total);
            advice_eq = max(chip.advice_eq, advice_eq);
            fixed_eq = max(chip.fixed_eq, fixed_eq);
        }

        let advice_neq = advice_total - advice_eq;
        let fixed_neq = fixed_total - fixed_eq;

        NumCols {
            advice_eq,
            advice_neq,
            fixed_eq,
            fixed_neq,
        }
    }

    pub fn configure<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
    ) -> (AdviceEq, AdviceNeq, FixedEq, FixedNeq) {
        let advice_eq = (0..self.advice_eq).map(|_| meta.advice_column()).collect();
        let advice_neq = (0..self.advice_neq).map(|_| meta.advice_column()).collect();
        let fixed_eq = (0..self.fixed_eq).map(|_| meta.fixed_column()).collect();
        let fixed_neq = (0..self.fixed_neq).map(|_| meta.fixed_column()).collect();
        (advice_eq, advice_neq, fixed_eq, fixed_neq)
    }
}
