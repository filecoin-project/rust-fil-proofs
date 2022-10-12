use std::marker::PhantomData;
use std::ops::Range;

use fil_halo2_gadgets::{
    boolean::{AssignedBit, Bit},
    ColumnCount, MaybeAssigned, NumCols,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Instance, Selector},
    poly::Rotation,
};

use crate::halo2::gadgets::insert::pick;

#[derive(Clone, Debug)]
pub struct ShiftConfig<F: FieldExt> {
    x_1: Column<Advice>,
    x_2: Column<Advice>,
    bit: Column<Advice>,
    y: Column<Advice>,
    s_shift: Selector,
    _f: PhantomData<F>,
}

pub struct ShiftChip<F: FieldExt> {
    config: ShiftConfig<F>,
}

impl<F: FieldExt> halo2_proofs::circuit::Chip<F> for ShiftChip<F> {
    type Config = ShiftConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ColumnCount for ShiftChip<F> {
    fn num_cols() -> NumCols {
        NumCols {
            advice_eq: 0,
            advice_neq: 4,
            fixed_eq: 0,
            fixed_neq: 0,
        }
    }
}

impl<F: FieldExt> ShiftChip<F> {
    pub fn construct(config: ShiftConfig<F>) -> Self {
        ShiftChip { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>, advice: &[Column<Advice>]) -> ShiftConfig<F> {
        // Check that we have enough advice columns.
        assert!(advice.len() >= 4);

        let xs = [advice[0], advice[1]];
        let bit = advice[2];
        let y = advice[3];

        let s_shift = meta.selector();
        meta.create_gate("s_shift", |meta| {
            let s_shift = meta.query_selector(s_shift);

            let x_1 = meta.query_advice(xs[0], Rotation::cur());
            let x_2 = meta.query_advice(xs[1], Rotation::cur());
            let bit = meta.query_advice(bit, Rotation::cur());
            let shifted = meta.query_advice(xs[0], Rotation::next());
            let y = meta.query_advice(y, Rotation::cur());

            let shifted_expr = pick(bit, x_1.clone(), x_2.clone());

            Constraints::with_selector(
                s_shift,
                [
                    ("check shifted", shifted_expr - shifted.clone()),
                    ("check unshifted", x_1 + x_2 - shifted - y),
                ],
            )
        });

        let [x_1, x_2] = xs;

        ShiftConfig {
            x_1,
            x_2,
            bit,
            y,
            s_shift,
            _f: PhantomData,
        }
    }

    pub fn witness_insert(
        &self,
        layouter: impl Layouter<F>,
        val: &Value<F>,
        uninserted: &[Value<F>],
        bits: &[Value<bool>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let val = MaybeAssigned::Unassigned(*val);

        let uninserted: Vec<MaybeAssigned<F, F>> = uninserted
            .iter()
            .copied()
            .map(MaybeAssigned::Unassigned)
            .collect();

        let bits: Vec<MaybeAssigned<Bit, F>> = bits
            .iter()
            .map(|bit| MaybeAssigned::Unassigned(bit.map(Bit)))
            .collect();

        self.insert_inner(layouter, &val, &uninserted, &bits)
    }

    pub fn insert(
        &self,
        layouter: impl Layouter<F>,
        val: &AssignedCell<F, F>,
        uninserted: &[Value<F>],
        bits: &[AssignedBit<F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let val = MaybeAssigned::Assigned(val.clone());

        let uninserted: Vec<MaybeAssigned<F, F>> = uninserted
            .iter()
            .copied()
            .map(MaybeAssigned::Unassigned)
            .collect();

        let bits: Vec<MaybeAssigned<Bit, F>> =
            bits.iter().cloned().map(MaybeAssigned::Assigned).collect();

        self.insert_inner(layouter, &val, &uninserted, &bits)
    }

    pub fn insert_with_pi_bits(
        &self,
        layouter: impl Layouter<F>,
        val: &AssignedCell<F, F>,
        uninserted: &[Value<F>],
        pi_col: Column<Instance>,
        // Public input row indices are absolute.
        pi_rows: Range<usize>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let val = MaybeAssigned::Assigned(val.clone());

        let uninserted: Vec<MaybeAssigned<F, F>> = uninserted
            .iter()
            .copied()
            .map(MaybeAssigned::Unassigned)
            .collect();

        let bits: Vec<MaybeAssigned<Bit, F>> =
            pi_rows.map(|row| MaybeAssigned::Pi(pi_col, row)).collect();
        assert_eq!(
            bits.len(),
            uninserted.len(),
            "number of public input rows provided does not equal number of shifts required",
        );

        self.insert_inner(layouter, &val, &uninserted, &bits)
    }

    fn insert_inner(
        &self,
        mut layouter: impl Layouter<F>,
        val: &MaybeAssigned<F, F>,
        uninserted: &[MaybeAssigned<F, F>],
        bits: &[MaybeAssigned<Bit, F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let num_shifts = uninserted.len();
        assert_eq!(
            bits.len(),
            num_shifts,
            "number of bits provided does not equal number of shifts required",
        );
        let arity = num_shifts + 1;

        layouter.assign_region(
            || format!("shift insert-{}", arity),
            |mut region| {
                let mut offset = 0;

                // Assign or copy the insertion value.
                let mut x_1 = match val {
                    MaybeAssigned::Unassigned(ref val) => {
                        region.assign_advice(|| "value", self.config.x_1, offset, || *val)?
                    }
                    MaybeAssigned::Assigned(ref val) => {
                        val.copy_advice(|| "copy value", &mut region, self.config.x_1, offset)?
                    }
                    _ => unimplemented!("insert value cannot be public input"),
                };

                let mut inserted = uninserted
                    .iter()
                    .zip(bits.iter())
                    .enumerate()
                    .map(|(i, (x_2, bit))| {
                        self.config.s_shift.enable(&mut region, offset)?;

                        // Assign or copy the uninserted array element.
                        let x_2 = match x_2 {
                            MaybeAssigned::Unassigned(ref elem) => region.assign_advice(
                                || format!("uninserted[{}]", i),
                                self.config.x_2,
                                offset,
                                || *elem,
                            )?,
                            MaybeAssigned::Assigned(ref elem) => elem.copy_advice(
                                || format!("copy uninserted[{}]", i),
                                &mut region,
                                self.config.x_2,
                                offset,
                            )?,
                            _ => unimplemented!("uninserted value cannot be public input"),
                        };

                        // Witness, copy, or copy from public inputs the shift bit.
                        //
                        // Assigning an advice cell from a public input can only assign a field
                        // element into the cell (`AssignedCell<F, F>`), whereas witnessing and
                        // copying advice can assign a `bool` into the cell
                        // (`AssignedCell<bool, F>`). To avoid this type mismatch, we convert the
                        // `AssignedCell`s to `Value<bool>`s.
                        let bit: Value<bool> = match bit {
                            MaybeAssigned::Unassigned(ref bit) => region
                                .assign_advice(
                                    || format!("bit_{}", i),
                                    self.config.bit,
                                    offset,
                                    || *bit,
                                )?
                                .value()
                                .map(bool::from),
                            MaybeAssigned::Assigned(ref bit) => bit
                                .copy_advice(
                                    || format!("copy bit_{}", i),
                                    &mut region,
                                    self.config.bit,
                                    offset,
                                )?
                                .value()
                                .map(bool::from),
                            MaybeAssigned::Pi(pi_col, pi_row) => region
                                .assign_advice_from_instance(
                                    || format!("copy bit_{} public input", i),
                                    *pi_col,
                                    *pi_row,
                                    self.config.bit,
                                    offset,
                                )?
                                .value()
                                .map(|field| {
                                    if field.is_zero_vartime() {
                                        false
                                    } else {
                                        assert_eq!(
                                            *field,
                                            F::one(),
                                            "bit_{} public input is not a bit (found={:?})",
                                            i,
                                            field,
                                        );
                                        true
                                    }
                                }),
                        };

                        // Calculate shifted and unshifted values.
                        let mut shifted = Value::unknown();
                        let mut y = Value::unknown();
                        bit.zip(x_1.value().zip(x_2.value()))
                            .map(|(bit, (&x_1, &x_2))| {
                                if bit {
                                    shifted = Value::known(x_1);
                                    y = Value::known(x_2);
                                } else {
                                    shifted = Value::known(x_2);
                                    y = Value::known(x_1);
                                }
                            });

                        // Assign unshifted value.
                        let y = region.assign_advice(
                            || format!("inserted[{}]", i),
                            self.config.y,
                            offset,
                            || y,
                        )?;

                        // Assign the shifted value in next row.
                        offset += 1;
                        x_1 = region.assign_advice(
                            || format!("shifted_{}", i),
                            self.config.x_1,
                            offset,
                            || shifted,
                        )?;

                        Ok(y)
                    })
                    .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()?;

                // Append last shifted value.
                inserted.push(x_1);
                Ok(inserted)
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};
    use rand::rngs::OsRng;

    use crate::halo2::{create_proof, verify_proof, CircuitRows, Halo2Field, Halo2Keypair};

    struct MyCircuit {
        value: Value<Fp>,
        uninserted: Vec<Value<Fp>>,
        bits: Vec<Value<bool>>,
    }

    impl Circuit<Fp> for MyCircuit {
        type Config = ShiftConfig<Fp>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            let uninserted_len = self.uninserted.len();
            assert!(uninserted_len != 0);
            assert_eq!(uninserted_len, self.bits.len());
            MyCircuit {
                value: Value::unknown(),
                uninserted: vec![Value::unknown(); uninserted_len],
                bits: vec![Value::unknown(); uninserted_len],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advice: Vec<Column<Advice>> = (0..4).map(|_| meta.advice_column()).collect();

            ShiftChip::configure(meta, &advice)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let shift_chip = ShiftChip::construct(config);

            let inserted =
                shift_chip.witness_insert(layouter, &self.value, &self.uninserted, &self.bits)?;

            // Calculate expected output.
            let expected = {
                let mut expected = self.uninserted.clone();
                let mut num_shifts = 0;
                for bit in &self.bits {
                    bit.map(|bit| {
                        if bit {
                            num_shifts += 1;
                        }
                    });
                }
                expected.insert(num_shifts, self.value);
                expected
            };

            // Check output.
            for (a, b) in inserted.iter().zip(expected.iter()) {
                a.value().zip(b.as_ref()).assert_if_known(|(a, b)| a == b);
            }

            Ok(())
        }
    }

    impl CircuitRows for MyCircuit {
        fn k(&self) -> u32 {
            if self.uninserted.len() == 1 {
                // Arity 2.
                3
            } else {
                // Arities 4 and 8.
                4
            }
        }
    }

    fn test_shift_chip_inner(arity: usize) {
        let mut circ = MyCircuit {
            value: Value::known(Fp::from(55)),
            uninserted: (0..arity - 1)
                .map(|i| Value::known(Fp::from(i as u64)))
                .collect(),
            bits: vec![Value::known(false); arity - 1],
        };
        let k = circ.k();

        // Test no shifts.
        let prover = MockProver::run(k, &circ, vec![]).expect("mock proving failed");
        assert!(prover.verify().is_ok());

        // Test each shift.
        for i in 0..arity - 1 {
            circ.bits[i] = Value::known(true);
            let prover = MockProver::run(k, &circ, vec![]).expect("mock proving failed");
            assert!(prover.verify().is_ok());
        }

        // Test proof generation.
        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&circ)
            .expect("failed to create halo2 keypair");
        let proof =
            create_proof(&keypair, circ, &[], &mut OsRng).expect("failed to create halo2 proof");
        verify_proof(&keypair, &proof, &[]).expect("failed to verify halo2 proof");
    }

    #[test]
    fn test_shift_chip() {
        test_shift_chip_inner(2);
        test_shift_chip_inner(4);
        test_shift_chip_inner(8);
    }
}
