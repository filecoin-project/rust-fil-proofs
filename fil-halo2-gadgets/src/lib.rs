pub mod boolean;
pub mod select;
pub mod sha256;
pub mod uint32;
pub mod utilities;

use std::cmp::max;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Value},
    plonk::{Advice, Column, ConstraintSystem, Fixed, Instance},
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

        let advice_total = max(
            self.0.advice_eq + self.0.advice_neq,
            chip.advice_eq + chip.advice_neq,
        );
        let advice_eq = max(self.0.advice_eq, chip.advice_eq);
        let advice_neq = advice_total - advice_eq;

        let fixed_total = max(
            self.0.fixed_eq + self.0.fixed_neq,
            chip.fixed_eq + chip.fixed_neq,
        );
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
        let advice_eq = (0..self.0.advice_eq)
            .map(|_| meta.advice_column())
            .collect();
        let advice_neq = (0..self.0.advice_neq)
            .map(|_| meta.advice_column())
            .collect();
        let fixed_eq = (0..self.0.fixed_eq).map(|_| meta.fixed_column()).collect();
        let fixed_neq = (0..self.0.fixed_neq).map(|_| meta.fixed_column()).collect();
        (advice_eq, advice_neq, fixed_eq, fixed_neq)
    }
}

impl<F, A, const STRENGTH: bool> ColumnCount for PoseidonChip<F, A, STRENGTH>
where
    F: FieldExt,
    A: Arity<F>,
{
    fn num_cols() -> NumCols {
        NumCols {
            advice_eq: Self::num_advice_eq(),
            advice_neq: Self::num_advice_neq(),
            fixed_eq: Self::num_fixed_eq(),
            fixed_neq: Self::num_fixed_neq(),
        }
    }
}

pub enum MaybeAssigned<T, F: FieldExt> {
    // An unassigned value that should be witnessed in a circuit.
    Unassigned(Value<T>),
    // An assigned value that should be copied in a circuit.
    Assigned(AssignedCell<T, F>),
    // A public input located in the cell `(instance_column, absolute_row)` that should be witnessed
    // in the circuit.
    Pi(Column<Instance>, usize),
}

pub struct AdviceIter {
    offset: usize,
    advice: Vec<Column<Advice>>,
    num_cols: usize,
    col_index: usize,
}

impl From<Vec<Column<Advice>>> for AdviceIter {
    fn from(advice: Vec<Column<Advice>>) -> Self {
        Self::new(0, advice)
    }
}

impl AdviceIter {
    pub fn new(offset: usize, advice: Vec<Column<Advice>>) -> Self {
        let num_cols = advice.len();
        assert_ne!(num_cols, 0);
        AdviceIter {
            offset,
            advice,
            col_index: 0,
            num_cols,
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> (usize, Column<Advice>) {
        if self.col_index == self.num_cols {
            self.offset += 1;
            self.col_index = 0;
        }
        let ret = (self.offset, self.advice[self.col_index]);
        self.col_index += 1;
        ret
    }
}
