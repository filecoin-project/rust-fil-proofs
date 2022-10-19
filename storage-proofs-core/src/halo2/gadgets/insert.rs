use std::marker::PhantomData;
use std::ops::Range;

use fil_halo2_gadgets::{
    boolean::{and, nor, AssignedBit, Bit},
    utilities::ternary,
    ColumnCount, MaybeAssigned, NumCols,
};
use filecoin_hashers::PoseidonArity;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Instance, Selector},
    poly::Rotation,
};

// Returns `a` if `bit` is set, otherwise returns `b`.
//
// Assumes `bit` is already boolean constrained.
#[inline]
pub fn pick<F: FieldExt>(bit: Expression<F>, a: Expression<F>, b: Expression<F>) -> Expression<F> {
    ternary(bit, a, b)
}

#[derive(Clone, Debug)]
pub struct InsertConfig<F, A>
where
    F: FieldExt,
    A: PoseidonArity<F>,
{
    uninserted: Vec<Column<Advice>>,
    value: Column<Advice>,
    index_bits: Vec<Column<Advice>>,
    inserted: Vec<Column<Advice>>,
    s_insert: Selector,
    _f: PhantomData<F>,
    _a: PhantomData<A>,
}

impl<F, A> InsertConfig<F, A>
where
    F: FieldExt,
    A: PoseidonArity<F>,
{
    // Changes the chip config's arity from `A` to `B`. This is safe only when arities `A` and `B`
    // are known to have the same constraint system configuration.
    pub fn transmute_arity<B: PoseidonArity<F>>(self) -> InsertConfig<F, B> {
        assert_eq!(A::to_usize(), B::to_usize());
        InsertConfig {
            uninserted: self.uninserted,
            value: self.value,
            index_bits: self.index_bits,
            inserted: self.inserted,
            s_insert: self.s_insert,
            _f: PhantomData,
            _a: PhantomData,
        }
    }
}

pub struct InsertChip<F, A>
where
    F: FieldExt,
    A: PoseidonArity<F>,
{
    config: InsertConfig<F, A>,
}

/*
impl<F, A> halo2_proofs::circuit::Chip<F> for InsertChip<F, A>
where
    F: FieldExt,
    A: PoseidonArity<F>,
{
    type Config = InsertConfig<F, A>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
*/

impl<F, A> ColumnCount for InsertChip<F, A>
where
    F: FieldExt,
    A: PoseidonArity<F>,
{
    fn num_cols() -> NumCols {
        let arity = A::to_usize();
        let index_bit_len = arity.trailing_zeros() as usize;
        NumCols {
            // The index bits, insertion value, and inserted array must be equality constrained.
            advice_eq: index_bit_len + 1 + arity,
            // Witness the uninserted array.
            advice_neq: arity - 1,
            fixed_eq: 0,
            fixed_neq: 0,
        }
    }
}

impl<F, A> InsertChip<F, A>
where
    F: FieldExt,
    A: PoseidonArity<F>,
{
    pub fn construct(config: InsertConfig<F, A>) -> Self {
        InsertChip { config }
    }

    // # Side Effects
    //
    // The first `Self::num_cols().advice_eq` columns of `advice_eq` will be equality enabled.
    #[allow(clippy::unwrap_used)]
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice_eq: &[Column<Advice>],
        advice_neq: &[Column<Advice>],
    ) -> InsertConfig<F, A> {
        let arity = A::to_usize();
        assert!([2, 4, 8].contains(&arity));

        let num_cols = Self::num_cols();

        // Check that we have enough equality enabled and total columns.
        let advice_eq_len = advice_eq.len();
        let advice_neq_len = advice_neq.len();
        assert!(advice_eq_len >= num_cols.advice_eq);
        assert!(advice_eq_len + advice_neq_len >= num_cols.advice_eq + num_cols.advice_neq);

        for col in &advice_eq[..num_cols.advice_eq] {
            meta.enable_equality(*col);
        }

        let mut advice = advice_eq.iter().chain(advice_neq.iter()).copied();

        let index_bit_len = arity.trailing_zeros() as usize;
        let index_bits: Vec<Column<Advice>> =
            (0..index_bit_len).map(|_| advice.next().unwrap()).collect();

        let value = advice.next().unwrap();

        let inserted: Vec<Column<Advice>> = (0..arity).map(|_| advice.next().unwrap()).collect();

        let uninserted: Vec<Column<Advice>> =
            (0..arity - 1).map(|_| advice.next().unwrap()).collect();

        let s_insert = meta.selector();

        match arity {
            2 => {
                meta.create_gate("insert_2", |meta| {
                    let s_insert = meta.query_selector(s_insert);

                    let a = meta.query_advice(value, Rotation::cur());
                    let b = meta.query_advice(uninserted[0], Rotation::cur());

                    let bit = meta.query_advice(index_bits[0], Rotation::cur());

                    let out_0 = meta.query_advice(inserted[0], Rotation::cur());
                    let out_1 = meta.query_advice(inserted[1], Rotation::cur());

                    let pick_0 = pick(bit.clone(), b.clone(), a.clone());
                    let pick_1 = pick(bit, a, b);

                    Constraints::with_selector(
                        s_insert,
                        [
                            ("check inserted 0", pick_0 - out_0),
                            ("check inserted 1", pick_1 - out_1),
                        ],
                    )
                });
            }
            4 => {
                meta.create_gate("insert_4", |meta| {
                    let s_insert = meta.query_selector(s_insert);

                    let a = meta.query_advice(value, Rotation::cur());
                    let b = meta.query_advice(uninserted[0], Rotation::cur());
                    let c = meta.query_advice(uninserted[1], Rotation::cur());
                    let d = meta.query_advice(uninserted[2], Rotation::cur());

                    let b0 = meta.query_advice(index_bits[0], Rotation::cur());
                    let b1 = meta.query_advice(index_bits[1], Rotation::cur());

                    let out_0 = meta.query_advice(inserted[0], Rotation::cur());
                    let out_1 = meta.query_advice(inserted[1], Rotation::cur());
                    let out_2 = meta.query_advice(inserted[2], Rotation::cur());
                    let out_3 = meta.query_advice(inserted[3], Rotation::cur());

                    let pick_0 = {
                        let tmp = pick(b0.clone(), b.clone(), a.clone());
                        pick(b1.clone(), b.clone(), tmp)
                    };

                    let pick_1 = {
                        let tmp = pick(b0.clone(), a.clone(), b);
                        pick(b1.clone(), c.clone(), tmp)
                    };

                    let pick_2 = {
                        let tmp = pick(b0.clone(), d.clone(), a.clone());
                        pick(b1.clone(), tmp, c)
                    };

                    let pick_3 = {
                        let tmp = pick(b0, a, d.clone());
                        pick(b1, tmp, d)
                    };

                    Constraints::with_selector(
                        s_insert,
                        [
                            ("check inserted 0", pick_0 - out_0),
                            ("check inserted 1", pick_1 - out_1),
                            ("check inserted 2", pick_2 - out_2),
                            ("check inserted 3", pick_3 - out_3),
                        ],
                    )
                });
            }
            8 => {
                meta.create_gate("insert_8", |meta| {
                    let s_insert = meta.query_selector(s_insert);

                    let a = meta.query_advice(value, Rotation::cur());
                    let b = meta.query_advice(uninserted[0], Rotation::cur());
                    let c = meta.query_advice(uninserted[1], Rotation::cur());
                    let d = meta.query_advice(uninserted[2], Rotation::cur());
                    let e = meta.query_advice(uninserted[3], Rotation::cur());
                    let f = meta.query_advice(uninserted[4], Rotation::cur());
                    let g = meta.query_advice(uninserted[5], Rotation::cur());
                    let h = meta.query_advice(uninserted[6], Rotation::cur());

                    let b0 = meta.query_advice(index_bits[0], Rotation::cur());
                    let b1 = meta.query_advice(index_bits[1], Rotation::cur());
                    let b2 = meta.query_advice(index_bits[2], Rotation::cur());

                    let out_0 = meta.query_advice(inserted[0], Rotation::cur());
                    let out_1 = meta.query_advice(inserted[1], Rotation::cur());
                    let out_2 = meta.query_advice(inserted[2], Rotation::cur());
                    let out_3 = meta.query_advice(inserted[3], Rotation::cur());
                    let out_4 = meta.query_advice(inserted[4], Rotation::cur());
                    let out_5 = meta.query_advice(inserted[5], Rotation::cur());
                    let out_6 = meta.query_advice(inserted[6], Rotation::cur());
                    let out_7 = meta.query_advice(inserted[7], Rotation::cur());

                    let b0_and_b1 = and(b0.clone(), b1.clone());
                    let b0_nor_b1 = nor(b0.clone(), b1.clone());

                    let tmp_0 = pick(b0_nor_b1.clone(), a.clone(), b.clone());
                    let pick_0 = pick(b2.clone(), b.clone(), tmp_0);

                    let tmp_1_0 = pick(b0.clone(), a.clone(), b);
                    let tmp_1_1 = pick(b1.clone(), c.clone(), tmp_1_0);
                    let pick_1 = pick(b2.clone(), c.clone(), tmp_1_1);

                    let tmp_2_0 = pick(b0.clone(), d.clone(), a.clone());
                    let tmp_2_1 = pick(b1.clone(), tmp_2_0, c);
                    let pick_2 = pick(b2.clone(), d.clone(), tmp_2_1);

                    let tmp_3 = pick(b0_and_b1.clone(), a.clone(), d);
                    let pick_3 = pick(b2.clone(), e.clone(), tmp_3);

                    let tmp_4 = pick(b0_nor_b1, a.clone(), f.clone());
                    let pick_4 = pick(b2.clone(), tmp_4, e);

                    let tmp_5_0 = pick(b0.clone(), a.clone(), f.clone());
                    let tmp_5_1 = pick(b1.clone(), g.clone(), tmp_5_0);
                    let pick_5 = pick(b2.clone(), tmp_5_1, f);

                    let tmp_6_0 = pick(b0, h.clone(), a.clone());
                    let tmp_6_1 = pick(b1, tmp_6_0, g.clone());
                    let pick_6 = pick(b2.clone(), tmp_6_1, g);

                    let tmp_7 = pick(b0_and_b1, a, h.clone());
                    let pick_7 = pick(b2, tmp_7, h);

                    Constraints::with_selector(
                        s_insert,
                        [
                            ("check inserted 0", pick_0 - out_0),
                            ("check inserted 1", pick_1 - out_1),
                            ("check inserted 2", pick_2 - out_2),
                            ("check inserted 3", pick_3 - out_3),
                            ("check inserted 4", pick_4 - out_4),
                            ("check inserted 5", pick_5 - out_5),
                            ("check inserted 6", pick_6 - out_6),
                            ("check inserted 7", pick_7 - out_7),
                        ],
                    )
                });
            }
            _ => unimplemented!(),
        };

        InsertConfig {
            uninserted,
            index_bits,
            value,
            inserted,
            s_insert,
            _f: PhantomData,
            _a: PhantomData,
        }
    }

    // Witnesses the insertion value and the uninserted array elements.
    pub fn insert_unassigned_value(
        &self,
        layouter: impl Layouter<F>,
        uninserted: &[Value<F>],
        value: &Value<F>,
        index_bits: &[AssignedBit<F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = MaybeAssigned::Unassigned(*value);
        let index_bits: Vec<MaybeAssigned<Bit, F>> = index_bits
            .iter()
            .cloned()
            .map(MaybeAssigned::Assigned)
            .collect();
        self.insert_inner(layouter, uninserted, value, &index_bits)
    }

    // Copies the insertion value and witnesses the uninserted array elements.
    pub fn insert_assigned_value(
        &self,
        layouter: impl Layouter<F>,
        uninserted: &[Value<F>],
        value: &AssignedCell<F, F>,
        index_bits: &[AssignedBit<F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = MaybeAssigned::Assigned(value.clone());
        let index_bits: Vec<MaybeAssigned<Bit, F>> = index_bits
            .iter()
            .cloned()
            .map(MaybeAssigned::Assigned)
            .collect();
        self.insert_inner(layouter, uninserted, value, &index_bits)
    }

    pub fn insert_unassigned_value_pi_bits(
        &self,
        layouter: impl Layouter<F>,
        uninserted: &[Value<F>],
        value: &Value<F>,
        pi_col: Column<Instance>,
        pi_rows: Range<usize>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = MaybeAssigned::Unassigned(*value);
        let index_bits: Vec<MaybeAssigned<Bit, F>> =
            pi_rows.map(|row| MaybeAssigned::Pi(pi_col, row)).collect();
        self.insert_inner(layouter, uninserted, value, &index_bits)
    }

    pub fn insert_assigned_value_pi_bits(
        &self,
        layouter: impl Layouter<F>,
        uninserted: &[Value<F>],
        value: &AssignedCell<F, F>,
        pi_col: Column<Instance>,
        pi_rows: Range<usize>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let value = MaybeAssigned::Assigned(value.clone());
        let index_bits: Vec<MaybeAssigned<Bit, F>> =
            pi_rows.map(|row| MaybeAssigned::Pi(pi_col, row)).collect();
        self.insert_inner(layouter, uninserted, value, &index_bits)
    }

    fn insert_inner(
        &self,
        mut layouter: impl Layouter<F>,
        uninserted: &[Value<F>],
        value: MaybeAssigned<F, F>,
        index_bits: &[MaybeAssigned<Bit, F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let arity = A::to_usize();
        assert_eq!(uninserted.len(), arity - 1);

        let index_bit_len = arity.trailing_zeros() as usize;
        assert_eq!(index_bits.len(), index_bit_len);

        layouter.assign_region(
            || format!("insert_{}", arity),
            |mut region| {
                let offset = 0;
                self.config.s_insert.enable(&mut region, offset)?;

                let index: usize = index_bits
                    .iter()
                    .zip(&self.config.index_bits)
                    .enumerate()
                    .map(|(i, (bit, col))| {
                        let bit: Value<bool> = match bit {
                            MaybeAssigned::Unassigned(ref bit) => region
                                .assign_advice(
                                    || format!("index_bits[{}]", i),
                                    *col,
                                    offset,
                                    || *bit,
                                )
                                .map(|bit| bit.value().map(bool::from))?,
                            MaybeAssigned::Assigned(ref bit) => bit
                                .copy_advice(
                                    || format!("copy index_bits[{}]", i),
                                    &mut region,
                                    *col,
                                    offset,
                                )
                                .map(|bit| bit.value().map(bool::from))?,
                            MaybeAssigned::Pi(pi_col, pi_row) => region
                                .assign_advice_from_instance(
                                    || format!("copy index_bits[{}] public input", i),
                                    *pi_col,
                                    *pi_row,
                                    *col,
                                    offset,
                                )
                                .map(|bit| {
                                    bit.value().map(|field| {
                                        if field.is_zero_vartime() {
                                            false
                                        } else {
                                            assert_eq!(
                                            *field, F::one(),
                                            "index_bits[{}] public input is not a bit (found={:?})",
                                            i,
                                            field,
                                        );
                                            true
                                        }
                                    })
                                })?,
                        };
                        let mut pow_2 = 0;
                        bit.map(|bit| {
                            pow_2 = (bit as usize) << i;
                        });
                        Ok(pow_2)
                    })
                    .collect::<Result<Vec<usize>, Error>>()?
                    .iter()
                    .sum();

                // Assign or copy insertion value.
                let value = match value {
                    MaybeAssigned::Unassigned(ref value) => {
                        region.assign_advice(|| "value", self.config.value, offset, || *value)?
                    }
                    MaybeAssigned::Assigned(ref value) => value.copy_advice(
                        || "copy value",
                        &mut region,
                        self.config.value,
                        offset,
                    )?,
                    _ => unreachable!(),
                };

                // Allocate uninserted array.
                for (i, (val, col)) in uninserted.iter().zip(&self.config.uninserted).enumerate() {
                    region.assign_advice(|| format!("uninserted[{}]", i), *col, offset, || *val)?;
                }

                let mut inserted: Vec<Value<F>> = uninserted.to_vec();
                inserted.insert(index, value.value().copied());

                // Allocate the inserted array.
                inserted
                    .iter()
                    .zip(&self.config.inserted)
                    .enumerate()
                    .map(|(i, (val, col))| {
                        region.assign_advice(|| format!("inserted[{}]", i), *col, offset, || *val)
                    })
                    .collect()
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use generic_array::typenum::{U2, U4, U8};
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        pasta::{Fp, Fq},
        plonk::Circuit,
    };
    use rand::rngs::OsRng;

    use crate::halo2::{create_proof, verify_proof, CircuitRows, Halo2Field, Halo2Keypair};

    #[derive(Clone, Debug)]
    struct MyConfig<F, A>
    where
        F: FieldExt,
        A: PoseidonArity<F>,
    {
        insert: InsertConfig<F, A>,
        advice_eq: Vec<Column<Advice>>,
    }

    struct MyCircuit<F, A>
    where
        F: FieldExt,
        A: PoseidonArity<F>,
    {
        uninserted: Vec<Value<F>>,
        value: Value<F>,
        index_bits: Vec<Value<bool>>,
        _a: PhantomData<A>,
    }

    impl<F, A> Circuit<F> for MyCircuit<F, A>
    where
        F: FieldExt,
        A: PoseidonArity<F>,
    {
        type Config = MyConfig<F, A>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            let arity = A::to_usize();
            let index_bit_len = arity.trailing_zeros() as usize;
            MyCircuit {
                uninserted: vec![Value::unknown(); arity - 1],
                value: Value::unknown(),
                index_bits: vec![Value::unknown(); index_bit_len],
                _a: PhantomData,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let num_cols = InsertChip::<F, A>::num_cols();

            let advice_eq: Vec<Column<Advice>> = (0..num_cols.advice_eq)
                .map(|_| meta.advice_column())
                .collect();

            let advice_neq: Vec<Column<Advice>> = (0..num_cols.advice_neq)
                .map(|_| meta.advice_column())
                .collect();

            let insert = InsertChip::<F, A>::configure(meta, &advice_eq, &advice_neq);

            MyConfig { insert, advice_eq }
        }

        #[allow(clippy::unwrap_used)]
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = InsertChip::<F, A>::construct(config.insert.clone());

            let (value, index_bits) = layouter.assign_region(
                || "value",
                |mut region| {
                    let offset = 0;

                    // Allocate insertion value.
                    let value = region.assign_advice(
                        || "value",
                        config.advice_eq[0],
                        offset,
                        || self.value,
                    )?;

                    // Allocate insertion index.
                    let index_bits = self
                        .index_bits
                        .iter()
                        .enumerate()
                        .map(|(i, bit)| {
                            region.assign_advice(
                                || format!("index_bit_{}", i),
                                config.advice_eq[1 + i],
                                offset,
                                || bit.map(Bit),
                            )
                        })
                        .collect::<Result<Vec<AssignedBit<F>>, Error>>()?;

                    Ok((value, index_bits))
                },
            )?;

            let inserted = chip.insert_assigned_value(
                layouter.namespace(|| "insert"),
                &self.uninserted,
                &value,
                &index_bits,
            )?;

            let mut index = 0;
            for (i, bit) in self.index_bits.iter().enumerate() {
                bit.map(|bit| {
                    index += (bit as usize) << i;
                });
            }
            let mut expected = self.uninserted.clone();
            expected.insert(index, self.value);

            for (val, expected) in inserted.iter().zip(expected.iter()) {
                val.value()
                    .zip(expected.as_ref())
                    .assert_if_known(|(val, expected)| val == expected);
            }

            Ok(())
        }
    }

    impl<F, A> CircuitRows for MyCircuit<F, A>
    where
        F: FieldExt,
        A: PoseidonArity<F>,
    {
        fn k(&self) -> u32 {
            3
        }
    }

    impl<F, A> MyCircuit<F, A>
    where
        F: FieldExt,
        A: PoseidonArity<F>,
    {
        fn with_witness(uninserted: &[F], value: F, index: usize) -> Self {
            let arity = A::to_usize();
            assert_eq!(uninserted.len(), arity - 1);

            let index_bit_len = arity.trailing_zeros() as usize;

            let index_bits: Vec<Value<bool>> = (0..index_bit_len)
                .map(|i| Value::known((index >> i) & 1 == 1))
                .collect();

            MyCircuit {
                uninserted: uninserted.iter().map(|elem| Value::known(*elem)).collect(),
                value: Value::known(value),
                index_bits,
                _a: PhantomData,
            }
        }
    }

    #[allow(clippy::unwrap_used)]
    fn test_insert_chip_inner<F, A>()
    where
        F: FieldExt,
        A: PoseidonArity<F>,
    {
        let arity = A::to_usize();
        let value = F::from(55);
        let uninserted: Vec<F> = (0..arity - 1).map(|i| F::from(i as u64)).collect();
        for i in 0..arity {
            let circ = MyCircuit::<F, A>::with_witness(&uninserted, value, i);
            let prover = MockProver::run(3, &circ, vec![]).unwrap();
            assert!(prover.verify().is_ok());
        }
    }

    #[test]
    fn test_insert_chip() {
        test_insert_chip_inner::<Fp, U2>();
        test_insert_chip_inner::<Fp, U4>();
        test_insert_chip_inner::<Fp, U8>();

        test_insert_chip_inner::<Fq, U2>();
        test_insert_chip_inner::<Fq, U4>();
        test_insert_chip_inner::<Fq, U8>();
    }

    #[ignore]
    #[test]
    fn test_insert_chip_prove_verify() {
        let len = 4u64;
        let arr: Vec<Fp> = (0..len - 1).map(Fp::from).collect();
        let insert_pos = 2;
        let insert_value = Fp::from(55);
        let circ = MyCircuit::<Fp, U4>::with_witness(&arr, insert_value, insert_pos);

        let blank_circuit = circ.without_witnesses();
        let keypair = Halo2Keypair::<<Fp as Halo2Field>::Affine, _>::create(&blank_circuit)
            .expect("failed to create halo2 keypair");

        let proof =
            create_proof(&keypair, circ, &[], &mut OsRng).expect("failed to create halo2 proof");

        verify_proof(&keypair, &proof, &[]).expect("failed to verify halo2 proof");
    }
}
