use std::marker::PhantomData;

use fil_halo2_gadgets::{
    boolean::{and, nor, AssignedBit},
    utilities::ternary,
    ColumnCount, NumCols,
};
use filecoin_hashers::PoseidonArity;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
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

    pub fn num_cols() -> NumCols {
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

    // Copies the insertion value and witnesses the uninserted array elements.
    #[allow(clippy::unwrap_used)]
    pub fn copy_insert(
        &self,
        mut layouter: impl Layouter<F>,
        uninserted: &[Option<F>],
        value: &AssignedCell<F, F>,
        index_bits: &[AssignedBit<F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let arity = A::to_usize();
        assert_eq!(uninserted.len(), arity - 1);

        let index_bit_len = arity.trailing_zeros() as usize;
        assert_eq!(index_bits.len(), index_bit_len);

        let index_opt: Option<usize> = index_bits
            .iter()
            .enumerate()
            .map(|(i, assigned_bit)| assigned_bit.value().map(|bit| (bit.0 as usize) << i))
            .reduce(|acc, opt| acc.zip(opt).map(|(acc, val)| acc + val))
            .unwrap();

        let mut inserted: Vec<Option<&F>> = uninserted.iter().map(|opt| opt.as_ref()).collect();
        inserted.insert(index_opt.unwrap_or(0), value.value());

        layouter.assign_region(
            || format!("insert_{}", arity),
            |mut region| {
                let row = 0;

                self.config.s_insert.enable(&mut region, row)?;

                // Copy the insertion index.
                for (i, (bit, col)) in index_bits
                    .iter()
                    .zip(self.config.index_bits.iter())
                    .enumerate()
                {
                    bit.copy_advice(|| format!("index bit {}", i), &mut region, *col, row)?;
                }

                // Copy insertion value.
                value.copy_advice(|| "value", &mut region, self.config.value, row)?;

                // Allocate uninserted array.
                for (i, opt) in uninserted.iter().enumerate() {
                    region.assign_advice(
                        || format!("uninserted {}", i),
                        self.config.uninserted[i],
                        row,
                        || opt.ok_or(Error::Synthesis),
                    )?;
                }

                // Allocate the inserted array.
                inserted
                    .iter()
                    .enumerate()
                    .map(|(i, opt)| {
                        region.assign_advice(
                            || format!("inserted {}", i),
                            self.config.inserted[i],
                            row,
                            || opt.cloned().ok_or(Error::Synthesis),
                        )
                    })
                    .collect()
            },
        )
    }

    // Witnesses the insertion value and the uninserted array elements.
    #[allow(clippy::unwrap_used)]
    pub fn witness_insert(
        &self,
        mut layouter: impl Layouter<F>,
        uninserted: &[Option<F>],
        value: &Option<F>,
        index_bits: &[AssignedBit<F>],
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let arity = A::to_usize();
        assert_eq!(uninserted.len(), arity - 1);

        let index_bit_len = arity.trailing_zeros() as usize;
        assert_eq!(index_bits.len(), index_bit_len);

        let index_opt: Option<usize> = index_bits
            .iter()
            .enumerate()
            .map(|(i, assigned_bit)| assigned_bit.value().map(|bit| (bit.0 as usize) << i))
            .reduce(|acc, opt| acc.zip(opt).map(|(acc, val)| acc + val))
            .unwrap();

        let mut inserted: Vec<Option<&F>> = uninserted.iter().map(|opt| opt.as_ref()).collect();
        inserted.insert(index_opt.unwrap_or(0), value.as_ref());

        layouter.assign_region(
            || format!("insert_{}", arity),
            |mut region| {
                let row = 0;

                self.config.s_insert.enable(&mut region, row)?;

                // Copy the insertion index.
                for (i, (bit, col)) in index_bits
                    .iter()
                    .zip(self.config.index_bits.iter())
                    .enumerate()
                {
                    bit.copy_advice(|| format!("index bit {}", i), &mut region, *col, row)?;
                }

                // Allocate insertion value.
                region.assign_advice(
                    || "value",
                    self.config.value,
                    row,
                    || value.ok_or(Error::Synthesis),
                )?;

                // Allocate uninserted array.
                for (i, opt) in uninserted.iter().enumerate() {
                    region.assign_advice(
                        || format!("uninserted {}", i),
                        self.config.uninserted[i],
                        row,
                        || opt.ok_or(Error::Synthesis),
                    )?;
                }

                // Allocate inserted array.
                inserted
                    .iter()
                    .enumerate()
                    .map(|(i, opt)| {
                        region.assign_advice(
                            || format!("inserted {}", i),
                            self.config.inserted[i],
                            row,
                            || opt.cloned().ok_or(Error::Synthesis),
                        )
                    })
                    .collect()
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use fil_halo2_gadgets::boolean::Bit;
    use generic_array::typenum::{U2, U4, U8};
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        pasta::{Fp, Fq},
        plonk::Circuit,
    };

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
        uninserted: Vec<Option<F>>,
        value: Option<F>,
        index_bits: Vec<Option<bool>>,
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
                uninserted: vec![None; arity - 1],
                value: None,
                index_bits: vec![None; index_bit_len],
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
                    let row = 0;

                    // Allocate insertion value.
                    let value = region.assign_advice(
                        || "value",
                        config.advice_eq[0],
                        row,
                        || self.value.ok_or(Error::Synthesis),
                    )?;

                    // Allocate insertion index.
                    let index_bits = self
                        .index_bits
                        .iter()
                        .enumerate()
                        .map(|(i, opt)| {
                            region.assign_advice(
                                || format!("index bit {}", i),
                                config.advice_eq[1 + i],
                                row,
                                || opt.map(Bit).ok_or(Error::Synthesis),
                            )
                        })
                        .collect::<Result<Vec<AssignedBit<F>>, Error>>()?;

                    Ok((value, index_bits))
                },
            )?;

            let inserted = chip.copy_insert(
                layouter.namespace(|| "insert"),
                &self.uninserted,
                &value,
                &index_bits,
            )?;

            let index = if self.index_bits.iter().any(|opt| opt.is_none()) {
                0
            } else {
                self.index_bits
                    .iter()
                    .enumerate()
                    .map(|(i, opt)| (opt.unwrap() as usize) << i)
                    .reduce(|acc, next| acc + next)
                    .unwrap()
            };

            let mut expected = self.uninserted.clone();
            expected.insert(index, self.value);
            assert_eq!(
                inserted
                    .iter()
                    .map(|asn| asn.value())
                    .collect::<Vec<Option<&F>>>(),
                expected
                    .iter()
                    .map(|opt| opt.as_ref())
                    .collect::<Vec<Option<&F>>>(),
            );

            Ok(())
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

            let index_bits: Vec<Option<bool>> = (0..index_bit_len)
                .map(|i| Some((index >> i) & 1 == 1))
                .collect();

            MyCircuit {
                uninserted: uninserted.iter().map(|elem| Some(*elem)).collect(),
                value: Some(value),
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
}
