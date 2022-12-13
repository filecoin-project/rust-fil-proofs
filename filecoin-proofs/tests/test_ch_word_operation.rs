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
fn test_ch_word_operation() {
    #[derive(Clone)]
    struct ChConfig {
        e: [Column<Advice>; 8],
        e_inv: [Column<Advice>; 8],
        f: [Column<Advice>; 8],
        g: [Column<Advice>; 8],
        ch: [Column<Advice>; 8],
        s_ch: Selector,
        s_word: Selector,
    }

    struct ChChip {
        config: ChConfig,
    }

    impl ChChip {
        fn construct(config: ChConfig) -> Self {
            ChChip { config }
        }

        #[allow(clippy::too_many_arguments)]
        fn configure(
            meta: &mut ConstraintSystem<Fp>,
            e: [Column<Advice>; 8],
            e_inv: [Column<Advice>; 8],
            f: [Column<Advice>; 8],
            g: [Column<Advice>; 8],
            ch: [Column<Advice>; 8],
            s_ch: Selector,
            s_word: Selector,
        ) -> ChConfig {
            meta.create_gate(
                "boolean constraint of 8 bits at once using 8 advice columns",
                |meta: &mut VirtualCells<Fp>| {
                    let s_word = meta.query_selector(s_word);

                    let mut bits_to_constraint =
                        e.iter().map(|col| meta.query_advice(*col, Rotation::cur()));

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

            meta.create_gate("ch", |meta: &mut VirtualCells<Fp>| {
                let s_ch = meta.query_selector(s_ch);

                let e = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(e[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let e_inv = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(e_inv[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let f = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(f[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let g = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(g[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                let ch = (0..8)
                    .into_iter()
                    .map(|index| meta.query_advice(ch[index], Rotation::cur()))
                    .collect::<Vec<Expression<Fp>>>();

                Constraints::with_selector(
                    s_ch,
                    [
                        (
                            "ch 0",
                            e_inv[0].clone() * g[0].clone() + e[0].clone() * f[0].clone()
                                - ch[0].clone(),
                        ),
                        (
                            "ch 1",
                            e_inv[1].clone() * g[1].clone() + e[1].clone() * f[1].clone()
                                - ch[1].clone(),
                        ),
                        (
                            "ch 2",
                            e_inv[2].clone() * g[2].clone() + e[2].clone() * f[2].clone()
                                - ch[2].clone(),
                        ),
                        (
                            "ch 3",
                            e_inv[3].clone() * g[3].clone() + e[3].clone() * f[3].clone()
                                - ch[3].clone(),
                        ),
                        (
                            "ch 4",
                            e_inv[4].clone() * g[4].clone() + e[4].clone() * f[4].clone()
                                - ch[4].clone(),
                        ),
                        (
                            "ch 5",
                            e_inv[5].clone() * g[5].clone() + e[5].clone() * f[5].clone()
                                - ch[5].clone(),
                        ),
                        (
                            "ch 6",
                            e_inv[6].clone() * g[6].clone() + e[6].clone() * f[6].clone()
                                - ch[6].clone(),
                        ),
                        (
                            "ch 7",
                            e_inv[7].clone() * g[7].clone() + e[7].clone() * f[7].clone()
                                - ch[7].clone(),
                        ),
                    ],
                )
            });

            ChConfig {
                e,
                e_inv,
                f,
                g,
                ch,
                s_ch,
                s_word,
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn ch_inner(
            &self,
            mut layouter: impl Layouter<Fp>,
            e: &[Option<AssignedCell<Bit, Fp>>],
            e_inv: &[Option<AssignedCell<Bit, Fp>>],
            f: &[Option<AssignedCell<Bit, Fp>>],
            g: &[Option<AssignedCell<Bit, Fp>>],
            ch: &[Option<AssignedCell<Bit, Fp>>],
            selector_offset: usize,
        ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
            layouter.assign_region(
                || "ch",
                |mut region| {
                    self.config.s_ch.enable(&mut region, selector_offset)?;

                    let mut ch_out = vec![];
                    for (index, ((((e, e_inv), f), g), ch)) in e
                        .iter()
                        .zip(e_inv.iter())
                        .zip(f.iter())
                        .zip(g.iter())
                        .zip(ch.iter())
                        .enumerate()
                    {
                        // assign e, e_inv, f, g, ch
                        for tuple in [
                            (e, self.config.e, "e"),
                            (e_inv, self.config.e_inv, "e_inv"),
                            (f, self.config.f, "f"),
                            (g, self.config.g, "g"),
                            (ch, self.config.ch, "ch"),
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
                            if tuple.2 == "ch" {
                                ch_out.push(assigned)
                            }
                        }
                    }
                    Ok(ch_out)
                },
            )
        }

        fn ch(
            &self,
            mut layouter: impl Layouter<Fp>,
            e: Value<[bool; 32]>,
            f: Value<[bool; 32]>,
            g: Value<[bool; 32]>,
            e_inv: Value<[bool; 32]>,
            ch: Value<[bool; 32]>,
        ) -> Result<AssignedWord, Error> {
            let e = self.load_word(layouter.namespace(|| "load e"), e)?;
            let e_inv = self.load_word(layouter.namespace(|| "load e_inv"), e_inv)?;
            let f = self.load_word(layouter.namespace(|| "load f"), f)?;
            let g = self.load_word(layouter.namespace(|| "load g"), g)?;
            let ch = self.load_word(layouter.namespace(|| "load ch"), ch)?;

            let ch_1 = self.ch_inner(
                layouter.namespace(|| "ch byte1"),
                &e.bits[0..8],
                &e_inv.bits[0..8],
                &f.bits[0..8],
                &g.bits[0..8],
                &ch.bits[0..8],
                0,
            )?;
            let ch_2 = self.ch_inner(
                layouter.namespace(|| "ch byte2"),
                &e.bits[8..16],
                &e_inv.bits[8..16],
                &f.bits[8..16],
                &g.bits[8..16],
                &ch.bits[8..16],
                1,
            )?;
            let ch_3 = self.ch_inner(
                layouter.namespace(|| "ch byte3"),
                &e.bits[16..24],
                &e_inv.bits[16..24],
                &f.bits[16..24],
                &g.bits[16..24],
                &ch.bits[16..24],
                2,
            )?;
            let ch_4 = self.ch_inner(
                layouter.namespace(|| "ch byte4"),
                &e.bits[24..32],
                &e_inv.bits[24..32],
                &f.bits[24..32],
                &g.bits[24..32],
                &ch.bits[24..32],
                3,
            )?;

            let ch = [ch_1, ch_2, ch_3, ch_4].concat();

            Ok(AssignedWord {
                bits: ch.into_iter().map(Some).collect(),
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
                            self.config.e[bit_index],
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
        e: Value<[bool; 32]>,
        f: Value<[bool; 32]>,
        g: Value<[bool; 32]>,
        expected_ch: Value<[bool; 32]>,
    }
    impl Circuit<Fp> for TestCircuit {
        type Config = ChConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let s_ch = meta.selector();
            let s_word = meta.selector();

            let e = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let e_inv = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let f = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let g = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            let ch = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            ChChip::configure(meta, e, e_inv, f, g, ch, s_ch, s_word)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = ChChip::construct(config);

            let e_inv: Value<[bool; 32]> = self.e.map(|e| {
                e.iter()
                    .map(|e| !e)
                    .collect::<Vec<bool>>()
                    .try_into()
                    .unwrap()
            });

            let ch_expected: Value<[bool; 32]> =
                self.e.zip(self.f).zip(self.g).map(|((e, f), g)| {
                    e.iter()
                        .zip(f.iter())
                        .zip(g.iter())
                        .map(|((e, f), g)| (e & f) ^ (!e & g))
                        .collect::<Vec<bool>>()
                        .try_into()
                        .unwrap()
                });

            let ch = chip.ch(
                layouter.namespace(|| "ch"),
                self.e,
                self.f,
                self.g,
                e_inv,
                ch_expected,
            )?;

            ch.value_u32()
                .zip(self.expected_ch)
                .map(|(actual, expected)| {
                    assert_eq!(actual, u32_from_bits_be(expected.as_slice()))
                });

            Ok(())
        }
    }

    let circuit = TestCircuit {
        e: Value::known([true; 32]),
        f: Value::known([false; 32]),
        g: Value::known([true; 32]),
        expected_ch: Value::known([false; 32]),
    };

    let prover = MockProver::run(7, &circuit, vec![]).expect("couldn't run mock prover");
    assert!(prover.verify().is_ok());
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
