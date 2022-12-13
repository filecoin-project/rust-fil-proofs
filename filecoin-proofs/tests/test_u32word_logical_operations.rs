use fil_halo2_gadgets::boolean::Bit;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Constraints, Error, Expression, Selector, SingleVerifier, VirtualCells,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;
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

#[derive(Clone)]
struct Sha256Config {
    word: [Column<Advice>; 8],
    s_word: Selector,
}

struct Sha256Chip {
    config: Sha256Config,
}

impl Sha256Chip {
    fn construct(config: Sha256Config) -> Self {
        Sha256Chip { config }
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        word: [Column<Advice>; 8],
        s_word: Selector,
    ) -> Sha256Config {
        meta.create_gate(
            "boolean constraint of 8 bits at once using 8 advice columns",
            |meta: &mut VirtualCells<Fp>| {
                let s_word = meta.query_selector(s_word);

                let mut bits_to_constraint = word
                    .iter()
                    .map(|col| meta.query_advice(*col, Rotation::cur()));

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
        Sha256Config { word, s_word }
    }

    fn load_word(
        &self,
        mut layouter: impl Layouter<Fp>,
        word: Value<[bool; 32]>,
    ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
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

        Ok([byte1, byte2, byte3, byte4].concat())
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
                        self.config.word[bit_index],
                        selector_offset,
                        || bit.map(|bit| Bit::from(bit)),
                    )?;
                    assigned_word.push(assigned);
                }

                Ok(assigned_word)
            },
        )
    }
}

#[derive(Clone)]
struct AssignedWordLogicalOperationsConfig {
    word_a: [Column<Advice>; 8],
    word_b: [Column<Advice>; 8],
    word_c: [Column<Advice>; 8],
    s_xor: Selector,
    s_and: Selector,
    s_not: Selector,
}
struct AssignedWordLogicalOperationsChip {
    config: AssignedWordLogicalOperationsConfig,
}
impl AssignedWordLogicalOperationsChip {
    fn construct(config: AssignedWordLogicalOperationsConfig) -> Self {
        AssignedWordLogicalOperationsChip { config }
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        word_a: [Column<Advice>; 8],
        word_b: [Column<Advice>; 8],
        word_c: [Column<Advice>; 8],
        s_xor: Selector,
        s_and: Selector,
        s_not: Selector,
    ) -> AssignedWordLogicalOperationsConfig {
        meta.create_gate("xor gate", |meta: &mut VirtualCells<Fp>| {
            let s_xor = meta.query_selector(s_xor);

            let a = (0..word_a.len())
                .into_iter()
                .map(|col_index| meta.query_advice(word_a[col_index], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            let b = (0..word_b.len())
                .into_iter()
                .map(|col_index| meta.query_advice(word_b[col_index], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            let out = (0..word_c.len())
                .into_iter()
                .map(|col_index| meta.query_advice(word_c[col_index], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            Constraints::with_selector(
                s_xor,
                vec![
                    (
                        "bit 0 xor",
                        (a[0].clone() + a[0].clone()) * b[0].clone() - a[0].clone() - b[0].clone()
                            + out[0].clone(),
                    ),
                    (
                        "bit 1 xor",
                        (a[1].clone() + a[1].clone()) * b[1].clone() - a[1].clone() - b[1].clone()
                            + out[1].clone(),
                    ),
                    (
                        "bit 2 xor",
                        (a[2].clone() + a[2].clone()) * b[2].clone() - a[2].clone() - b[2].clone()
                            + out[2].clone(),
                    ),
                    (
                        "bit 3 xor",
                        (a[3].clone() + a[3].clone()) * b[3].clone() - a[3].clone() - b[3].clone()
                            + out[3].clone(),
                    ),
                    (
                        "bit 4 xor",
                        (a[4].clone() + a[4].clone()) * b[4].clone() - a[4].clone() - b[4].clone()
                            + out[4].clone(),
                    ),
                    (
                        "bit 5 xor",
                        (a[5].clone() + a[5].clone()) * b[5].clone() - a[5].clone() - b[5].clone()
                            + out[5].clone(),
                    ),
                    (
                        "bit 6 xor",
                        (a[6].clone() + a[6].clone()) * b[6].clone() - a[6].clone() - b[6].clone()
                            + out[6].clone(),
                    ),
                    (
                        "bit 7 xor",
                        (a[7].clone() + a[7].clone()) * b[7].clone() - a[7].clone() - b[7].clone()
                            + out[7].clone(),
                    ),
                ],
            )
        });

        meta.create_gate("and gate", |meta: &mut VirtualCells<Fp>| {
            let s_and = meta.query_selector(s_and);

            let a = (0..word_a.len())
                .into_iter()
                .map(|col_index| meta.query_advice(word_a[col_index], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            let b = (0..word_b.len())
                .into_iter()
                .map(|col_index| meta.query_advice(word_b[col_index], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            let out = (0..word_c.len())
                .into_iter()
                .map(|col_index| meta.query_advice(word_c[col_index], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            Constraints::with_selector(
                s_and,
                vec![
                    ("bit 0 and", a[0].clone() * b[0].clone() - out[0].clone()),
                    ("bit 1 and", a[1].clone() * b[1].clone() - out[1].clone()),
                    ("bit 2 and", a[2].clone() * b[2].clone() - out[2].clone()),
                    ("bit 3 and", a[3].clone() * b[3].clone() - out[3].clone()),
                    ("bit 4 and", a[4].clone() * b[4].clone() - out[4].clone()),
                    ("bit 5 and", a[5].clone() * b[5].clone() - out[5].clone()),
                    ("bit 6 and", a[6].clone() * b[6].clone() - out[6].clone()),
                    ("bit 7 and", a[7].clone() * b[7].clone() - out[7].clone()),
                ],
            )
        });

        meta.create_gate("not gate", |meta: &mut VirtualCells<Fp>| {
            let s_not = meta.query_selector(s_not);

            let a = (0..word_a.len())
                .into_iter()
                .map(|col_index| meta.query_advice(word_a[col_index], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            let out = (0..word_c.len())
                .into_iter()
                .map(|col_index| meta.query_advice(word_c[col_index], Rotation::cur()))
                .collect::<Vec<Expression<Fp>>>();

            Constraints::with_selector(
                s_not,
                vec![
                    ("bit 0 not", a[0].clone() * out[0].clone()),
                    ("bit 1 not", a[1].clone() * out[1].clone()),
                    ("bit 2 not", a[2].clone() * out[2].clone()),
                    ("bit 3 not", a[3].clone() * out[3].clone()),
                    ("bit 4 not", a[4].clone() * out[4].clone()),
                    ("bit 5 not", a[5].clone() * out[5].clone()),
                    ("bit 6 not", a[6].clone() * out[6].clone()),
                    ("bit 7 not", a[7].clone() * out[7].clone()),
                ],
            )
        });

        AssignedWordLogicalOperationsConfig {
            word_a,
            word_b,
            word_c,
            s_xor,
            s_and,
            s_not,
        }
    }

    fn not(&self, mut layouter: impl Layouter<Fp>, a: AssignedWord) -> Result<AssignedWord, Error> {
        let byte1 = self.not_inner(layouter.namespace(|| "byte 1"), &a.bits[0..8], 0)?;
        let byte2 = self.not_inner(layouter.namespace(|| "byte 2"), &a.bits[8..16], 1)?;
        let byte3 = self.not_inner(layouter.namespace(|| "byte 3"), &a.bits[16..24], 2)?;
        let byte4 = self.not_inner(layouter.namespace(|| "byte 4"), &a.bits[24..32], 3)?;

        let bytes = [byte1, byte2, byte3, byte4].concat();

        Ok(AssignedWord {
            bits: bytes.into_iter().map(Some).collect(),
        })
    }

    fn not_inner(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &[Option<AssignedCell<Bit, Fp>>],
        selector_offset: usize,
    ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
        assert_eq!(a.len(), 8);
        assert_eq!(a.len(), self.config.word_a.len());
        layouter.assign_region(
            || "not",
            |mut region| {
                self.config.s_not.enable(&mut region, selector_offset)?;

                let mut output = vec![];
                for (bit_index, bit) in a.iter().enumerate() {
                    let bit = bit.as_ref();

                    // assign input
                    let assigned_bit = match bit {
                        Some(v) => v.copy_advice(
                            || "assign a",
                            &mut region,
                            self.config.word_a[bit_index],
                            selector_offset,
                        ),
                        None => region.assign_advice(
                            || "assign a",
                            self.config.word_a[bit_index],
                            selector_offset,
                            || Value::known(Bit::from(false)),
                        ),
                    }?;

                    // compute and assign result at once
                    let expected_bit = assigned_bit.value().map(|bit| Bit::from(!bit.0));

                    let not_bit_assigned = region.assign_advice(
                        || "assign result",
                        self.config.word_c[bit_index],
                        selector_offset,
                        || expected_bit,
                    )?;

                    output.push(not_bit_assigned);
                }
                Ok(output)
            },
        )
    }

    fn and(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedWord,
        b: AssignedWord,
    ) -> Result<AssignedWord, Error> {
        let byte1 = self.and_inner(
            layouter.namespace(|| "and byte1"),
            &a.bits[0..8],
            &b.bits[0..8],
            0,
        )?;
        let byte2 = self.and_inner(
            layouter.namespace(|| "and byte2"),
            &a.bits[8..16],
            &b.bits[8..16],
            1,
        )?;
        let byte3 = self.and_inner(
            layouter.namespace(|| "and byte3"),
            &a.bits[16..24],
            &b.bits[16..24],
            2,
        )?;
        let byte4 = self.and_inner(
            layouter.namespace(|| "and byte4"),
            &a.bits[24..32],
            &b.bits[24..32],
            3,
        )?;

        let bytes = [byte1, byte2, byte3, byte4].concat();

        Ok(AssignedWord {
            bits: bytes.into_iter().map(Some).collect(),
        })
    }

    fn and_inner(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &[Option<AssignedCell<Bit, Fp>>],
        b: &[Option<AssignedCell<Bit, Fp>>],
        selector_offset: usize,
    ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), self.config.word_a.len());
        assert_eq!(b.len(), self.config.word_b.len());

        layouter.assign_region(
            || "xor",
            |mut region| {
                self.config.s_and.enable(&mut region, selector_offset)?;

                let mut output = vec![];
                for (index, (a, b)) in a.iter().zip(b.iter()).enumerate() {
                    let bit_a = a.as_ref();
                    let bit_b = b.as_ref();
                    let a = match bit_a {
                        Some(a) => a.copy_advice(
                            || "assign a",
                            &mut region,
                            self.config.word_a[index],
                            selector_offset,
                        ),
                        None => region.assign_advice(
                            || "assign a",
                            self.config.word_a[index],
                            selector_offset,
                            || Value::known(Bit::from(false)),
                        ),
                    }?;

                    let b = match bit_b {
                        Some(b) => b.copy_advice(
                            || "assign b",
                            &mut region,
                            self.config.word_b[index],
                            selector_offset,
                        ),
                        None => region.assign_advice(
                            || "assign b",
                            self.config.word_b[index],
                            selector_offset,
                            || Value::known(Bit::from(false)),
                        ),
                    }?;

                    let and = a
                        .value()
                        .zip(b.value())
                        .map(|(a, b)| Bit(bool::from(a) & bool::from(b)));

                    let and_assigned = region.assign_advice(
                        || "assign result",
                        self.config.word_c[index],
                        selector_offset,
                        || and,
                    )?;
                    output.push(and_assigned);
                }

                Ok(output)
            },
        )
    }

    fn xor(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedWord,
        b: AssignedWord,
    ) -> Result<AssignedWord, Error> {
        let byte1 = self.xor_inner(
            layouter.namespace(|| "xor byte1"),
            &a.bits[0..8],
            &b.bits[0..8],
            0,
        )?;
        let byte2 = self.xor_inner(
            layouter.namespace(|| "xor byte2"),
            &a.bits[8..16],
            &b.bits[8..16],
            1,
        )?;
        let byte3 = self.xor_inner(
            layouter.namespace(|| "xor byte3"),
            &a.bits[16..24],
            &b.bits[16..24],
            2,
        )?;
        let byte4 = self.xor_inner(
            layouter.namespace(|| "xor byte4"),
            &a.bits[24..32],
            &b.bits[24..32],
            3,
        )?;

        let bytes = [byte1, byte2, byte3, byte4].concat();

        Ok(AssignedWord {
            bits: bytes.into_iter().map(Some).collect(),
        })
    }

    fn xor_inner(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: &[Option<AssignedCell<Bit, Fp>>],
        b: &[Option<AssignedCell<Bit, Fp>>],
        selector_offset: usize,
    ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), self.config.word_a.len());
        assert_eq!(b.len(), self.config.word_b.len());

        layouter.assign_region(
            || "xor",
            |mut region| {
                self.config.s_xor.enable(&mut region, selector_offset)?;

                let mut output = vec![];
                for (index, (a, b)) in a.iter().zip(b.iter()).enumerate() {
                    let bit_a = a.as_ref();
                    let bit_b = b.as_ref();
                    let a = match bit_a {
                        Some(a) => a.copy_advice(
                            || "assign a",
                            &mut region,
                            self.config.word_a[index],
                            selector_offset,
                        ),
                        None => region.assign_advice(
                            || "assign a",
                            self.config.word_a[index],
                            selector_offset,
                            || Value::known(Bit::from(false)),
                        ),
                    }?;

                    let b = match bit_b {
                        Some(b) => b.copy_advice(
                            || "assign b",
                            &mut region,
                            self.config.word_b[index],
                            selector_offset,
                        ),
                        None => region.assign_advice(
                            || "assign b",
                            self.config.word_b[index],
                            selector_offset,
                            || Value::known(Bit::from(false)),
                        ),
                    }?;

                    let xor = a
                        .value()
                        .zip(b.value())
                        .map(|(a, b)| Bit(bool::from(a) ^ bool::from(b)));

                    let xor_assigned = region.assign_advice(
                        || "assign result",
                        self.config.word_c[index],
                        selector_offset,
                        || xor,
                    )?;
                    output.push(xor_assigned);
                }

                Ok(output)
            },
        )
    }
}

#[test]
fn test_word_not() {
    struct TestCircuit {
        word: Value<[bool; 32]>,
    }

    impl TestCircuit {
        fn k(&self) -> u32 {
            5
        }
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = (Sha256Config, AssignedWordLogicalOperationsConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            TestCircuit {
                word: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            meta.instance_column(); //unused

            let word = (0..8 * 3)
                .into_iter()
                .map(|_| {
                    let word = meta.advice_column();
                    meta.enable_equality(word);
                    word
                })
                .collect::<Vec<Column<Advice>>>();

            let s_xor = meta.selector();
            let s_and = meta.selector();
            let s_not = meta.selector();

            let config_1 = AssignedWordLogicalOperationsChip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                [
                    word[8], word[9], word[10], word[11], word[12], word[13], word[14], word[15],
                ],
                [
                    word[16], word[17], word[18], word[19], word[20], word[21], word[22], word[23],
                ],
                s_xor,
                s_and,
                s_not,
            );

            let s_word = meta.selector();

            let config_2 = Sha256Chip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                s_word,
            );

            (config_2, config_1)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let word_operations_chip = AssignedWordLogicalOperationsChip::construct(config.1);
            let word_assignment_chip = Sha256Chip::construct(config.0);

            let word_1 =
                word_assignment_chip.load_word(layouter.namespace(|| "load word 1"), self.word)?;

            let word_1_inverted = word_operations_chip.not(
                layouter.namespace(|| "not"),
                AssignedWord {
                    bits: word_1.into_iter().map(Some).collect(),
                },
            )?;

            word_1_inverted
                .value_u32()
                .zip(self.word)
                .map(|(result, word)| assert_eq!(result, !u32_from_bits_be(word.as_slice())));

            Ok(())
        }
    }

    let circuit = TestCircuit {
        word: Value::known([false; 32]),
    };

    let prover =
        MockProver::run(circuit.k(), &circuit, vec![vec![]]).expect("couldn't run mocked prover");
    assert!(prover.verify().is_ok());

    fn test(word: [bool; 32], use_circuit_prover_for_keygen: bool) -> bool {
        let circuit = TestCircuit {
            word: Value::known(word),
        };

        let public_inputs = vec![];

        let k = circuit.k();

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover_for_keygen {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = circuit.without_witnesses();
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        };

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

        let now = std::time::Instant::now();
        // Create a proof
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&public_inputs[..]]],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proving_time = now.elapsed();

        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let now = std::time::Instant::now();
        let result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok();
        let verifying_time = now.elapsed();

        println!(
            "Proof size: {} bytes; k: {}; proving time: {:.2?}; verifying time: {:.2?}",
            proof.len(),
            k,
            proving_time,
            verifying_time
        );

        result
    }

    fn positive_test(word: [bool; 32], use_circuit_prover_for_keygen: bool) {
        println!("positive test ...");
        assert!(test(word, use_circuit_prover_for_keygen));
        println!("OK");
    }

    let word = [false; 32];
    positive_test(word, true);
    positive_test(word, false);
}

#[test]
fn test_word_xor() {
    struct TestCircuit {
        word1: Value<[bool; 32]>,
        word2: Value<[bool; 32]>,
    }

    impl TestCircuit {
        fn k(&self) -> u32 {
            6
        }
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = (Sha256Config, AssignedWordLogicalOperationsConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            TestCircuit {
                word1: Value::unknown(),
                word2: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            meta.instance_column(); //unused

            let word = (0..8 * 3)
                .into_iter()
                .map(|_| {
                    let word = meta.advice_column();
                    meta.enable_equality(word);
                    word
                })
                .collect::<Vec<Column<Advice>>>();

            let s_xor = meta.selector();
            let s_and = meta.selector();
            let s_not = meta.selector();

            let config_1 = AssignedWordLogicalOperationsChip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                [
                    word[8], word[9], word[10], word[11], word[12], word[13], word[14], word[15],
                ],
                [
                    word[16], word[17], word[18], word[19], word[20], word[21], word[22], word[23],
                ],
                s_xor,
                s_and,
                s_not,
            );

            let s_word = meta.selector();

            let config_2 = Sha256Chip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                s_word,
            );

            (config_2, config_1)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let word_operations_chip = AssignedWordLogicalOperationsChip::construct(config.1);
            let word_assignment_chip = Sha256Chip::construct(config.0);

            let word_1 =
                word_assignment_chip.load_word(layouter.namespace(|| "load word 1"), self.word1)?;

            let word_2 =
                word_assignment_chip.load_word(layouter.namespace(|| "load word 2"), self.word2)?;

            let result = word_operations_chip.xor(
                layouter.namespace(|| "xor"),
                AssignedWord {
                    bits: word_1.into_iter().map(Some).collect(),
                },
                AssignedWord {
                    bits: word_2.into_iter().map(Some).collect(),
                },
            )?;

            let expected = self
                .word1
                .zip(self.word2)
                .map(|(word1, word2)| u32_from_bits_be(&word1) ^ u32_from_bits_be(&word2));

            result
                .value_u32()
                .zip(expected)
                .map(|(computed, expected)| assert_eq!(computed, expected));

            Ok(())
        }
    }

    let circuit = TestCircuit {
        word1: Value::known([false; 32]),
        word2: Value::known([false; 32]),
    };

    let prover =
        MockProver::run(circuit.k(), &circuit, vec![vec![]]).expect("couldn't run mocked prover");
    assert!(prover.verify().is_ok());

    fn test(word1: [bool; 32], word2: [bool; 32], use_circuit_prover_for_keygen: bool) -> bool {
        let circuit = TestCircuit {
            word1: Value::known(word1),
            word2: Value::known(word2),
        };

        let public_inputs = vec![];

        let k = circuit.k();

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover_for_keygen {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = circuit.without_witnesses();
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        };

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

        let now = std::time::Instant::now();
        // Create a proof
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&public_inputs[..]]],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proving_time = now.elapsed();

        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let now = std::time::Instant::now();
        let result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok();
        let verifying_time = now.elapsed();

        println!(
            "Proof size: {} bytes; k: {}; proving time: {:.2?}; verifying time: {:.2?}",
            proof.len(),
            k,
            proving_time,
            verifying_time
        );

        result
    }

    fn positive_test(word1: [bool; 32], word2: [bool; 32], use_circuit_prover_for_keygen: bool) {
        println!("positive test ...");
        assert!(test(word1, word2, use_circuit_prover_for_keygen));
        println!("OK");
    }

    let word1 = [false; 32];
    let word2 = [false; 32];
    positive_test(word1, word2, true);
    positive_test(word1, word2, false);
}

#[test]
fn test_word_and() {
    struct TestCircuit {
        word1: Value<[bool; 32]>,
        word2: Value<[bool; 32]>,
    }

    impl TestCircuit {
        fn k(&self) -> u32 {
            6
        }
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = (Sha256Config, AssignedWordLogicalOperationsConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            TestCircuit {
                word1: Value::unknown(),
                word2: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            meta.instance_column(); //unused

            let word = (0..8 * 3)
                .into_iter()
                .map(|_| {
                    let word = meta.advice_column();
                    meta.enable_equality(word);
                    word
                })
                .collect::<Vec<Column<Advice>>>();

            let s_xor = meta.selector();
            let s_and = meta.selector();
            let s_not = meta.selector();

            let config_1 = AssignedWordLogicalOperationsChip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                [
                    word[8], word[9], word[10], word[11], word[12], word[13], word[14], word[15],
                ],
                [
                    word[16], word[17], word[18], word[19], word[20], word[21], word[22], word[23],
                ],
                s_xor,
                s_and,
                s_not,
            );

            let s_word = meta.selector();

            let config_2 = Sha256Chip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                s_word,
            );

            (config_2, config_1)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let word_operations_chip = AssignedWordLogicalOperationsChip::construct(config.1);
            let word_assignment_chip = Sha256Chip::construct(config.0);

            let word_1 =
                word_assignment_chip.load_word(layouter.namespace(|| "load word 1"), self.word1)?;

            let word_2 =
                word_assignment_chip.load_word(layouter.namespace(|| "load word 2"), self.word2)?;

            let result = word_operations_chip.and(
                layouter.namespace(|| "and"),
                AssignedWord {
                    bits: word_1.into_iter().map(Some).collect(),
                },
                AssignedWord {
                    bits: word_2.into_iter().map(Some).collect(),
                },
            )?;

            let expected = self
                .word1
                .zip(self.word2)
                .map(|(word1, word2)| u32_from_bits_be(&word1) & u32_from_bits_be(&word2));

            result
                .value_u32()
                .zip(expected)
                .map(|(computed, expected)| assert_eq!(computed, expected));

            Ok(())
        }
    }

    let circuit = TestCircuit {
        word1: Value::known([true; 32]),
        word2: Value::known([true; 32]),
    };

    let prover =
        MockProver::run(circuit.k(), &circuit, vec![vec![]]).expect("couldn't run mocked prover");
    assert!(prover.verify().is_ok());

    fn test(word1: [bool; 32], word2: [bool; 32], use_circuit_prover_for_keygen: bool) -> bool {
        let circuit = TestCircuit {
            word1: Value::known(word1),
            word2: Value::known(word2),
        };

        let public_inputs = vec![];

        let k = circuit.k();

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover_for_keygen {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = circuit.without_witnesses();
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        };

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

        let now = std::time::Instant::now();
        // Create a proof
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&[&public_inputs[..]]],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proving_time = now.elapsed();

        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let now = std::time::Instant::now();
        let result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok();
        let verifying_time = now.elapsed();

        println!(
            "Proof size: {} bytes; k: {}; proving time: {:.2?}; verifying time: {:.2?}",
            proof.len(),
            k,
            proving_time,
            verifying_time
        );

        result
    }

    fn positive_test(word1: [bool; 32], word2: [bool; 32], use_circuit_prover_for_keygen: bool) {
        println!("positive test ...");
        assert!(test(word1, word2, use_circuit_prover_for_keygen));
        println!("OK");
    }

    let word1 = [false; 32];
    let word2 = [false; 32];
    positive_test(word1, word2, true);
    positive_test(word1, word2, false);
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
