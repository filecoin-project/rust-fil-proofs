pub mod boolean;
pub mod select;
pub mod sha256;
pub mod uint32;
pub mod utilities;

use std::cmp::max;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::AssignedCell,
    plonk::{Advice, Column, ConstraintSystem, Fixed},
};
use neptune::{halo2_circuit::PoseidonChip, Arity};

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

pub enum WitnessOrCopy<T, F: FieldExt> {
    Witness(Option<T>),
    Copy(AssignedCell<T, F>),
}

pub struct AdviceIter {
    offset: usize,
    cols: Vec<Column<Advice>>,
    col_index: usize,
}

impl Iterator for AdviceIter {
    type Item = (usize, Column<Advice>);

    fn next(&mut self) -> Option<Self::Item> {
        let offset_col = match self.cols.get(self.col_index) {
            Some(col) => (self.offset, *col),
            None => {
                self.offset += 1;
                self.col_index = 0;
                (self.offset, self.cols[self.col_index])
            }
        };
        self.col_index += 1;
        Some(offset_col)
    }
}

impl AdviceIter {
    pub fn new(offset: usize, cols: Vec<Column<Advice>>) -> Self {
        assert!(!cols.is_empty());
        AdviceIter {
            offset,
            cols,
            col_index: 0,
        }
    }
}


pub trait ColumnCount {
    fn num_cols() -> NumCols;
}

#[derive(Default)]
pub struct ColumnBuilder(NumCols);

impl ColumnBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_chip<C: ColumnCount>(mut self) -> Self {
        let chip = C::num_cols();

        let advice_total =
            max(self.0.advice_eq + self.0.advice_neq, chip.advice_eq + chip.advice_neq);
        let advice_eq = max(self.0.advice_eq, chip.advice_eq);
        let advice_neq = advice_total - advice_eq;

        let fixed_total = max(self.0.fixed_eq + self.0.fixed_neq, chip.fixed_eq + chip.fixed_neq);
        let fixed_eq = max(chip.fixed_eq, self.0.fixed_eq);
        let fixed_neq = fixed_total - fixed_eq;

        self.0 = NumCols {
            advice_eq,
            advice_neq,
            fixed_eq,
            fixed_neq,
        };

        self
    }

    pub fn create_columns<F: FieldExt>(
        &self,
        meta: &mut ConstraintSystem<F>,
    ) -> (AdviceEq, AdviceNeq, FixedEq, FixedNeq) {
        let advice_eq = (0..self.0.advice_eq).map(|_| meta.advice_column()).collect();
        let advice_neq = (0..self.0.advice_neq).map(|_| meta.advice_column()).collect();
        let fixed_eq = (0..self.0.fixed_eq).map(|_| meta.fixed_column()).collect();
        let fixed_neq = (0..self.0.fixed_neq).map(|_| meta.fixed_column()).collect();
        (advice_eq, advice_neq, fixed_eq, fixed_neq)
    }
}

impl<F: FieldExt, A: Arity<F>> ColumnCount for PoseidonChip<F, A> {
    fn num_cols() -> NumCols {
        let width = A::to_usize() + 1;
        NumCols {
            advice_eq: width,
            advice_neq: 1,
            // Poseidon requires `2 * width` fixed columns.
            fixed_eq: 1,
            fixed_neq: 2 * width - 1,
        }
    }
}
