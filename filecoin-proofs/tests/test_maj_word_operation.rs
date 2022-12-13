use fil_halo2_gadgets::boolean::Bit;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Selector,
    VirtualCells,
};
use halo2_proofs::poly::Rotation;
use std::convert::TryInto;

#[derive(Clone, Debug)]
struct AssignedWord {
    bits: Vec<Option<AssignedCell<Bit, Fp>>>,
}

impl AssignedWord {
    pub fn value_u32(&self) -> Value<u32> {
        self.bits
            .iter()
            .filter(|bit| bit.is_some())
            .enumerate()
            .fold(Value::known(0), |acc, (i, bit)| {
                acc + bit
                    .as_ref()
                    .unwrap()
                    .value()
                    .map(|bit| (bool::from(bit) as u32) << i)
            })
    }
}

#[test]
fn test_maj_word_operation() {
    #[derive(Clone)]
    struct MajConfig {
        a: [Column<Advice>; 8],
        a_inv: [Column<Advice>; 8],
        b: [Column<Advice>; 8],
        b_inv: [Column<Advice>; 8],
        c: [Column<Advice>; 8],
        maj: [Column<Advice>; 8],
        s_maj: Selector,
        s_word: Selector,
    }

    struct MajChip {
        config: MajConfig,
    }

    impl MajChip {
        fn construct(config: MajConfig) -> Self {
            MajChip { config }
        }

        #[allow(clippy::too_many_arguments)]
        fn configure(
            meta: &mut ConstraintSystem<Fp>,
            a: [Column<Advice>; 8],
            a_inv: [Column<Advice>; 8],
            b: [Column<Advice>; 8],
            b_inv: [Column<Advice>; 8],
            c: [Column<Advice>; 8],
            maj: [Column<Advice>; 8],
            s_maj: Selector,
            s_word: Selector,
        ) -> MajConfig {
            meta.create_gate(
                "boolean constraint of 8 bits at once using 8 advice columns",
                |meta: &mut VirtualCells<Fp>| {
                    let s_word = meta.query_selector(s_word);

                    let mut bits_to_constraint =
                        a.iter().map(|col| meta.query_advice(*col, Rotation::cur()));

                    Constraints::with_selector(
                        s_word,
                        [
                            ("0", bool_check(bits_to_constraint.next().unwrap())),
                            ("1", bool_check(bits_to_constraint.next().unwrap())),
                            ("2", bool_check(bits_to_constraint.next().unwrap())),
                            ("3", bool_check(bits_to_constraint.next().unwrap())),
                            ("4", bool_check(bits_to_constraint.next().unwrap())),
                            ("5", bool_check(bits_to_constraint.next().unwrap())),
                            ("6", bool_check(bits_to_constraint.next().unwrap())),
                            ("7", bool_check(bits_to_constraint.next().unwrap())),
                        ],
                    )
                },
            );

            meta.create_gate("maj", |meta: &mut VirtualCells<Fp>| {
                let s_maj = meta.query_selector(s_maj);

                let a = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(a[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let a_inv = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(a_inv[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let b = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(b[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let b_inv = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(b_inv[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let c = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(c[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let maj = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(maj[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let a_b = a
                    .into_iter()
                    .zip(b.into_iter())
                    .map(|(a, b)| a * b)
                    .collect::<Vec<Expression<Fp>>>();

                Constraints::with_selector(
                    s_maj,
                    [
                        (
                            "maj 0",
                            a_b[0].clone()
                                + c[0].clone()
                                    * (Expression::Constant(Fp::one())
                                        - a_inv[0].clone() * b_inv[0].clone()
                                        - a_b[0].clone())
                                - maj[0].clone(),
                        ),
                        (
                            "maj 1",
                            a_b[1].clone()
                                + c[1].clone()
                                    * (Expression::Constant(Fp::one())
                                        - a_inv[1].clone() * b_inv[1].clone()
                                        - a_b[1].clone())
                                - maj[1].clone(),
                        ),
                        (
                            "maj 2",
                            a_b[2].clone()
                                + c[2].clone()
                                    * (Expression::Constant(Fp::one())
                                        - a_inv[2].clone() * b_inv[2].clone()
                                        - a_b[2].clone())
                                - maj[2].clone(),
                        ),
                        (
                            "maj 3",
                            a_b[3].clone()
                                + c[3].clone()
                                    * (Expression::Constant(Fp::one())
                                        - a_inv[3].clone() * b_inv[3].clone()
                                        - a_b[3].clone())
                                - maj[3].clone(),
                        ),
                        (
                            "maj 4",
                            a_b[4].clone()
                                + c[4].clone()
                                    * (Expression::Constant(Fp::one())
                                        - a_inv[4].clone() * b_inv[4].clone()
                                        - a_b[4].clone())
                                - maj[4].clone(),
                        ),
                        (
                            "maj 5",
                            a_b[5].clone()
                                + c[5].clone()
                                    * (Expression::Constant(Fp::one())
                                        - a_inv[5].clone() * b_inv[5].clone()
                                        - a_b[5].clone())
                                - maj[5].clone(),
                        ),
                        (
                            "maj 6",
                            a_b[6].clone()
                                + c[6].clone()
                                    * (Expression::Constant(Fp::one())
                                        - a_inv[6].clone() * b_inv[6].clone()
                                        - a_b[6].clone())
                                - maj[6].clone(),
                        ),
                        (
                            "maj 7",
                            a_b[7].clone()
                                + c[7].clone()
                                    * (Expression::Constant(Fp::one())
                                        - a_inv[7].clone() * b_inv[7].clone()
                                        - a_b[7].clone())
                                - maj[7].clone(),
                        ),
                    ],
                )
            });

            MajConfig {
                a,
                a_inv,
                b,
                b_inv,
                c,
                maj,
                s_maj,
                s_word,
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn maj_inner(
            &self,
            mut layouter: impl Layouter<Fp>,
            a: &[Option<AssignedCell<Bit, Fp>>],
            a_inv: &[Option<AssignedCell<Bit, Fp>>],
            b: &[Option<AssignedCell<Bit, Fp>>],
            b_inv: &[Option<AssignedCell<Bit, Fp>>],
            c: &[Option<AssignedCell<Bit, Fp>>],
            maj: &[Option<AssignedCell<Bit, Fp>>],
            selector_offset: usize,
        ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
            layouter.assign_region(
                || "maj",
                |mut region| {
                    self.config.s_maj.enable(&mut region, selector_offset)?;

                    let mut maj_out = vec![];
                    for (index, (((((a, a_inv), b), b_inv), c), maj)) in a
                        .iter()
                        .zip(a_inv.iter())
                        .zip(b.iter())
                        .zip(b_inv.iter())
                        .zip(c.iter())
                        .zip(maj.iter())
                        .enumerate()
                    {
                        // assign a, a_inv, b, b_inv, c, maj
                        for tuple in [
                            (a, self.config.a, "a"),
                            (a_inv, self.config.a_inv, "a_inv"),
                            (b, self.config.b, "b"),
                            (b_inv, self.config.b_inv, "b_inv"),
                            (c, self.config.c, "c"),
                            (maj, self.config.maj, "maj"),
                        ] {
                            let bit = tuple.0.as_ref();
                            let assigned = match bit {
                                Some(bit) => bit.copy_advice(
                                    || format!("assign {}", tuple.2),
                                    &mut region,
                                    tuple.1[index],
                                    selector_offset,
                                ),
                                None => region.assign_advice(
                                    || "",
                                    tuple.1[index],
                                    selector_offset,
                                    || Value::known(Bit::from(false)),
                                ),
                            }?;
                            if tuple.2 == "maj" {
                                maj_out.push(assigned)
                            }
                        }
                    }
                    Ok(maj_out)
                },
            )
        }

        #[allow(clippy::too_many_arguments)]
        fn maj(
            &self,
            mut layouter: impl Layouter<Fp>,
            a: Value<[bool; 32]>,
            a_inv: Value<[bool; 32]>,
            b: Value<[bool; 32]>,
            b_inv: Value<[bool; 32]>,
            c: Value<[bool; 32]>,
            maj_expected: Value<[bool; 32]>,
        ) -> Result<AssignedWord, Error> {
            let a = self.load_word(layouter.namespace(|| "load a"), a)?;
            let a_inv = self.load_word(layouter.namespace(|| "load a_inv"), a_inv)?;
            let b = self.load_word(layouter.namespace(|| "load b"), b)?;
            let b_inv = self.load_word(layouter.namespace(|| "load b_inv"), b_inv)?;
            let c = self.load_word(layouter.namespace(|| "load c"), c)?;
            let maj = self.load_word(layouter.namespace(|| "load maj"), maj_expected)?;

            let maj_1 = self.maj_inner(
                layouter.namespace(|| "maj byte1"),
                &a.bits[0..8],
                &a_inv.bits[0..8],
                &b.bits[0..8],
                &b_inv.bits[0..8],
                &c.bits[0..8],
                &maj.bits[0..8],
                0,
            )?;
            let maj_2 = self.maj_inner(
                layouter.namespace(|| "maj byte2"),
                &a.bits[8..16],
                &a_inv.bits[8..16],
                &b.bits[8..16],
                &b_inv.bits[8..16],
                &c.bits[8..16],
                &maj.bits[8..16],
                1,
            )?;
            let maj_3 = self.maj_inner(
                layouter.namespace(|| "maj byte3"),
                &a.bits[16..24],
                &a_inv.bits[16..24],
                &b.bits[16..24],
                &b_inv.bits[16..24],
                &c.bits[16..24],
                &maj.bits[16..24],
                2,
            )?;
            let maj_4 = self.maj_inner(
                layouter.namespace(|| "maj byte4"),
                &a.bits[24..32],
                &a_inv.bits[24..32],
                &b.bits[24..32],
                &b_inv.bits[24..32],
                &c.bits[24..32],
                &maj.bits[24..32],
                3,
            )?;

            let maj = [maj_1, maj_2, maj_3, maj_4].concat();

            Ok(AssignedWord {
                bits: maj.into_iter().map(Some).collect(),
            })
        }

        fn load_word(
            &self,
            mut layouter: impl Layouter<Fp>,
            word: Value<[bool; 32]>,
        ) -> Result<AssignedWord, Error> {
            let word = word.transpose_array();

            let byte1 = self.load_word_byte(
                layouter.namespace(|| "load 1 byte"),
                word[0..8].try_into().unwrap(),
                0,
            )?;

            let byte2 = self.load_word_byte(
                layouter.namespace(|| "load 2 byte"),
                word[8..16].try_into().unwrap(),
                1,
            )?;

            let byte3 = self.load_word_byte(
                layouter.namespace(|| "load 3 byte"),
                word[16..24].try_into().unwrap(),
                2,
            )?;

            let byte4 = self.load_word_byte(
                layouter.namespace(|| "load 4 byte"),
                word[24..32].try_into().unwrap(),
                3,
            )?;

            Ok(AssignedWord {
                bits: [byte1, byte2, byte3, byte4]
                    .concat()
                    .into_iter()
                    .map(Some)
                    .collect(),
            })
        }

        fn load_word_byte(
            &self,
            mut layouter: impl Layouter<Fp>,
            word: [Value<bool>; 8],
            selector_offset: usize,
        ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
            layouter.assign_region(
                || "load word",
                |mut region| {
                    self.config.s_word.enable(&mut region, selector_offset)?;

                    let mut assigned_word = vec![];
                    for (bit_index, bit) in word.iter().enumerate() {
                        let assigned = region.assign_advice(
                            || format!("bit {}", bit_index),
                            self.config.a[bit_index],
                            selector_offset,
                            || bit.map(Bit::from),
                        )?;
                        assigned_word.push(assigned);
                    }

                    Ok(assigned_word)
                },
            )
        }
    }

    struct TestCircuit {
        a: Value<[bool; 32]>,
        b: Value<[bool; 32]>,
        c: Value<[bool; 32]>,
        expected_maj: Value<[bool; 32]>,
    }
    impl Circuit<Fp> for TestCircuit {
        type Config = MajConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let s_maj = meta.selector();
            let s_word = meta.selector();

            let a = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let a_inv = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let b = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let b_inv = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let c = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let maj = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            MajChip::configure(meta, a, a_inv, b, b_inv, c, maj, s_maj, s_word)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = MajChip::construct(config);

            let a_inv: Value<[bool; 32]> = self.a.map(|a| {
                a.iter()
                    .map(|a| !a)
                    .collect::<Vec<bool>>()
                    .try_into()
                    .unwrap()
            });

            let b_inv: Value<[bool; 32]> = self.b.map(|b| {
                b.iter()
                    .map(|b| !b)
                    .collect::<Vec<bool>>()
                    .try_into()
                    .unwrap()
            });

            let maj_expected: Value<[bool; 32]> =
                self.a.zip(self.b).zip(self.c).map(|((a, b), c)| {
                    a.iter()
                        .zip(b.iter())
                        .zip(c.iter())
                        .map(|((a, b), c)| (a & b) ^ (b & c) ^ (a & c))
                        .collect::<Vec<bool>>()
                        .try_into()
                        .unwrap()
                });

            let maj = chip.maj(
                layouter.namespace(|| "maj"),
                self.a,
                a_inv,
                self.b,
                b_inv,
                self.c,
                maj_expected,
            )?;

            maj.value_u32()
                .zip(self.expected_maj)
                .map(|(actual, expected)| {
                    assert_eq!(actual, u32_from_bits_be(expected.as_slice()))
                });

            Ok(())
        }
    }

    for test_input in [
        (false, false, false, false),
        (false, false, true, false),
        (false, true, false, false),
        (false, true, true, true),
        (true, false, false, false),
        (true, false, true, true),
        (true, true, false, true),
        (true, true, true, true),
    ]
    .iter()
    {
        let circuit = TestCircuit {
            a: Value::known([test_input.0; 32]),
            b: Value::known([test_input.1; 32]),
            c: Value::known([test_input.2; 32]),
            expected_maj: Value::known([test_input.3; 32]),
        };

        let prover = MockProver::run(7, &circuit, vec![]).expect("couldn't run mock prover");
        assert!(prover.verify().is_ok());
    }
}

fn u32_from_bits_be(bits: &[bool]) -> u32 {
    assert_eq!(bits.len(), 32);

    let mut u32_word = 0u32;
    for bit in bits {
        u32_word <<= 1;
        if *bit {
            u32_word |= 1;
        }
    }
    u32_word
}
