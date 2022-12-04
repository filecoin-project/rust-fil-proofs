pub mod boolean;
pub mod merkle;
pub mod select;
pub mod sha256;
pub mod uint32;
pub mod utilities;

use std::cmp::max;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Expression, Fixed, Instance},
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

#[derive(Debug, Clone, Copy, Default, PartialEq)]
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

    pub fn num_cols(&self) -> NumCols {
        self.0
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

#[derive(Clone, Debug)]
pub enum MaybeAssigned<T, F: FieldExt> {
    // An unassigned value that should be witnessed in a circuit.
    Unassigned(Value<T>),
    // An assigned value that should be copied in a circuit.
    Assigned(AssignedCell<T, F>),
    // A public input located in the cell `(instance_column, absolute_row)` that should be witnessed
    // in the circuit.
    Pi(Column<Instance>, usize),
}

impl<T, F: FieldExt> From<Value<T>> for MaybeAssigned<T, F> {
    fn from(value: Value<T>) -> Self {
        MaybeAssigned::Unassigned(value)
    }
}

impl<T, F: FieldExt> From<AssignedCell<T, F>> for MaybeAssigned<T, F> {
    fn from(asn: AssignedCell<T, F>) -> Self {
        MaybeAssigned::Assigned(asn)
    }
}

impl<T, F: FieldExt> From<MaybeAssigned<T, F>> for AssignedCell<T, F> {
    fn from(maybe_asn: MaybeAssigned<T, F>) -> Self {
        match maybe_asn {
            MaybeAssigned::Assigned(asn) => asn,
            _ => panic!("cannot convert unassigned `MaybeAssigned` into `AssignedCell`"),
        }
    }
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

impl Iterator for AdviceIter {
    type Item = (usize, Column<Advice>);

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next())
    }
}

// Packs little-endian integers into an integer using the provided radix; the packed integer must be
// less than the field modulus.
pub fn pack_ints<F: FieldExt>(mut ints: Vec<Expression<F>>, radix: u64) -> Expression<F> {
    let shl = F::from(radix);
    ints.drain(..)
        .rev()
        .fold(Expression::Constant(F::zero()), |acc, int| {
            acc * Expression::Constant(shl) + int
        })
}

// Converts an assigned `F` to an assigned `V` for any `V` that implements `From<&F>`.
//
// This function can be used to convert an advice cell, that was assigned from an instance cell, to
// have a desired inner value type.
pub(crate) fn convert_assigned_f<V, F>(asn_f: AssignedCell<F, F>) -> AssignedCell<V, F>
where
    for<'a> V: From<&'a F> + std::fmt::Debug,
    F: FieldExt,
{
    use std::{mem, ptr, slice};

    use halo2_proofs::circuit::Cell;

    // Get assigned cell's raw bytes.
    let cell = asn_f.cell();
    let cell_bytes: &[u8] = {
        let cell_ptr = (&cell as *const Cell) as *const u8;
        unsafe { slice::from_raw_parts(cell_ptr, mem::size_of::<Cell>()) }
    };

    // Convert assigned `Value<F>` to `Value<V>`.
    let val = asn_f.value().map(V::from);

    // Get `Value<V>`'s raw bytes.
    let val_bytes: &[u8] = {
        let val_ptr = (&val as *const Value<V>) as *const u8;
        unsafe { slice::from_raw_parts(val_ptr, mem::size_of::<Value<V>>()) }
    };

    // Join `Cell`'s and `Value<V>`'s raw bytes.
    let mut raw_bytes: Vec<u8> = cell_bytes.iter().chain(val_bytes).copied().collect();
    raw_bytes.resize(mem::size_of::<AssignedCell<V, F>>(), 0);
    assert_eq!(raw_bytes.len(), mem::size_of::<AssignedCell<V, F>>());

    // Convert new raw bytes into `AssignedCell<Value<V>>`.
    let asn_v = unsafe { ptr::read(raw_bytes.as_ptr() as *const AssignedCell<V, F>) };
    assert_eq!(format!("{:?}", asn_v.cell()), format!("{:?}", asn_f.cell()));
    assert_eq!(format!("{:?}", asn_v.value()), format!("{:?}", val));
    asn_v
}

pub trait CircuitSize<F: FieldExt>: Circuit<F> {
    fn num_rows(&self) -> usize;

    fn k(&self) -> u32 {
        let mut meta = ConstraintSystem::default();
        Self::configure(&mut meta);
        let num_rows = self.num_rows() + meta.blinding_factors() + 1;
        (num_rows as f32).log2().floor() as u32 + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        pasta::Fp,
        plonk::Error,
    };

    use crate::{boolean::AssignedBit, sha256::compress::AssignedU32};

    #[test]
    #[ignore]
    fn test_convert_assigned_f() {
        struct MyCircuit;

        impl Circuit<Fp> for MyCircuit {
            type Config = Column<Advice>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                meta.advice_column()
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                layouter.assign_region(
                    || "region",
                    |mut region| {
                        let mut offset = 0;

                        let zero: AssignedCell<Fp, Fp> = region.assign_advice(
                            || "zero",
                            config,
                            offset,
                            || Value::known(Fp::zero()),
                        )?;
                        offset += 1;
                        let cell = zero.cell();
                        let zero: AssignedBit<Fp> = convert_assigned_f(zero);
                        assert_eq!(format!("{:?}", zero.cell()), format!("{:?}", cell));
                        zero.value().assert_if_known(|bit| !bool::from(*bit));

                        let one: AssignedCell<Fp, Fp> = region.assign_advice(
                            || "one",
                            config,
                            offset,
                            || Value::known(Fp::one()),
                        )?;
                        offset += 1;
                        let cell = one.cell();
                        let one: AssignedBit<Fp> = convert_assigned_f(one);
                        assert_eq!(format!("{:?}", one.cell()), format!("{:?}", cell));
                        one.value().assert_if_known(|bit| bool::from(*bit));

                        let word: AssignedCell<Fp, Fp> = region.assign_advice(
                            || "u32",
                            config,
                            offset,
                            || Value::known(Fp::from(u32::max_value() as u64)),
                        )?;
                        let cell = word.cell();
                        let word: AssignedU32<Fp> = convert_assigned_f(word);
                        assert_eq!(format!("{:?}", word.cell()), format!("{:?}", cell));
                        word.value()
                            .assert_if_known(|word| u32::from(*word) == u32::max_value());

                        Ok(())
                    },
                )
            }
        }

        let prover = MockProver::<Fp>::run(4, &MyCircuit, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
