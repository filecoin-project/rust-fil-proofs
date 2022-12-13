use fil_halo2_gadgets::boolean::Bit;
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Constraints, Error, Selector, SingleVerifier, VirtualCells,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;
use std::convert::TryInto;

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
                        || bit.map(Bit::from),
                    )?;
                    assigned_word.push(assigned);
                }

                Ok(assigned_word)
            },
        )
    }
}

#[test]
fn test_load_32bit_word() {
    struct TestCircuit {
        word: Value<[bool; 32]>,
    }

    impl TestCircuit {
        fn k(&self) -> u32 {
            4
        }
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = Sha256Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            TestCircuit {
                word: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            meta.instance_column(); //unused

            let word = (0..8)
                .into_iter()
                .map(|_| {
                    let col = meta.advice_column();
                    meta.enable_equality(col);
                    col
                })
                .collect::<Vec<Column<Advice>>>();

            let s_word = meta.selector();

            Sha256Chip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                s_word,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = Sha256Chip::construct(config);

            chip.load_word(layouter.namespace(|| "load word"), self.word)?;

            Ok(())
        }
    }

    let circuit = TestCircuit {
        word: Value::known([false; 32]),
    };

    let prover =
        MockProver::run(circuit.k(), &circuit, vec![vec![]]).expect("couldn't run mock prover");
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
