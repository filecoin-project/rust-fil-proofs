use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error, Fixed, Instance, Selector, SingleVerifier,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;
use std::marker::PhantomData;

trait NumericInstruction<F: FieldExt>: Chip<F> {
    type Num;

    fn load_private(&self, layouter: impl Layouter<F>, a: Value<F>) -> Result<Self::Num, Error>;

    fn load_constant(&self, layouter: impl Layouter<F>, constant: F) -> Result<Self::Num, Error>;

    fn mul(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error>;

    fn expose_public(
        &self,
        layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error>;
}

struct FieldChip<F: FieldExt> {
    config: FieldConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for FieldChip<F> {
    type Config = FieldConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Clone, Debug)]
struct FieldConfig {
    advice: [Column<Advice>; 2],
    instance: Column<Instance>,
    s_mul: Selector,
    s_add: Selector,
}

impl<F: FieldExt> FieldChip<F> {
    fn construct(config: <Self as Chip<F>>::Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 2],
        instance: Column<Instance>,
        constant: Column<Fixed>,
    ) -> <Self as Chip<F>>::Config {
        meta.enable_equality(instance);

        meta.enable_constant(constant);

        for column in &advice {
            meta.enable_equality(*column);
        }

        let multiplication_selector = meta.selector();

        meta.create_gate("mul", |meta| {
            // To implement multiplication, we need three advice cells and a selector cell. We arrange them like so:
            //
            // | a0  | a1  | s_mul |
            // |-----|-----|-------|
            // | lhs | rhs | s_mul |
            // | out |     |       |
            //
            // Gates may refer to any relative offsets we want, but each distinct offset adds a cost to the proof. The most common offsets are 0 (the
            // current row), 1 (the next row), and -1 (the previous row), for which 'Rotation' has specific constructors.
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let s_mul = meta.query_selector(multiplication_selector);

            // Finally, we return the polynomial expressions that constrain this gate.
            // For our multiplication gate, we only need a single polynomial constraint
            // The polynomial expressions returned from 'create_gate' will be constrained by
            // the proving system to equal zero. Our expression has the following properties::
            // - When s_mul = 0, any value is allowed in lhs, rhs, and out.
            // - When s_mul != 0, this constrains lhs * rhs = out.
            vec![s_mul * (lhs * rhs - out)]
        });

        let addition_selector = meta.selector();
        meta.create_gate("add", |meta| {
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[0], Rotation::next());
            let addition_selector_expression = meta.query_selector(addition_selector);
            vec![addition_selector_expression * (lhs + rhs - out)]
        });

        FieldConfig {
            advice,
            instance,
            s_mul: multiplication_selector,
            s_add: addition_selector,
        }
    }
}

#[derive(Clone)]
struct Number<F: FieldExt>(AssignedCell<F, F>);

impl<F: FieldExt> NumericInstruction<F> for FieldChip<F> {
    type Num = Number<F>;
    fn load_private(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<F>,
    ) -> Result<Self::Num, Error> {
        let config = self.config();
        layouter.assign_region(
            || "load private",
            |mut region| {
                region
                    .assign_advice(|| "private input", config.advice[0], 0, || value)
                    .map(Number)
            },
        )
    }

    fn load_constant(
        &self,
        mut layouter: impl Layouter<F>,
        constant: F,
    ) -> Result<Self::Num, Error> {
        let config = self.config();

        layouter.assign_region(
            || "load constant",
            |mut region| {
                region
                    .assign_advice_from_constant(|| "constant value", config.advice[0], 0, constant)
                    .map(Number)
            },
        )
    }

    fn mul(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Self::Num, Error> {
        let config = self.config();
        layouter.assign_region(
            || "mul",
            |mut region: Region<'_, F>| {
                config.s_mul.enable(&mut region, 0)?;

                a.0.copy_advice(|| "lhs", &mut region, config.advice[0], 0)?;
                b.0.copy_advice(|| "rhs", &mut region, config.advice[1], 0)?;

                let value = a.0.value().copied() * b.0.value();

                region
                    .assign_advice(|| "lhs * rhs", config.advice[0], 1, || value)
                    .map(Number)
            },
        )
    }

    fn add(
        &self,
        mut layouter: impl Layouter<F>,
        a: Self::Num,
        b: Self::Num,
    ) -> Result<Number<F>, Error> {
        let config = self.config();

        layouter.assign_region(
            || "add",
            |mut region: Region<'_, F>| {
                let mut offset = 0;

                // Enable addition to be checked in the current row
                config.s_add.enable(&mut region, offset)?;

                // Copy the addition operands into the current row
                let lhs =
                    a.0.copy_advice(|| "lhs", &mut region, config.advice[0], offset)?;
                let rhs =
                    b.0.copy_advice(|| "rhs", &mut region, config.advice[1], offset)?;

                // Assign the output of addition in the next row
                offset += 1;
                let out = lhs.value().zip(rhs.value()).map(|(lhs, rhs)| *lhs + *rhs);

                region
                    .assign_advice(|| "lhs + rhs", config.advice[0], offset, || out)
                    .map(Number)
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        num: Self::Num,
        row: usize,
    ) -> Result<(), Error> {
        let config = self.config();
        layouter.constrain_instance(num.0.cell(), config.instance, row)
    }
}

#[derive(Default, Copy, Clone)]
struct MyCircuit<F: FieldExt> {
    constant: F,
    a: Value<F>,
    b: Value<F>,
}

impl<F: FieldExt> MyCircuit<F> {
    fn circuit_prover(constant: F, a: Value<F>, b: Value<F>) -> Self {
        MyCircuit { constant, a, b }
    }

    fn circuit_verifier(constant: F) -> Self {
        MyCircuit {
            constant,
            a: Value::unknown(),
            b: Value::unknown(),
        }
    }

    fn public_inputs(&self, c: F) -> Vec<F> {
        vec![c]
    }
}

impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
    type Config = FieldConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];

        let instance = meta.instance_column();

        let constant = meta.fixed_column();

        FieldChip::configure(meta, advice, instance, constant)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let field_chip = FieldChip::<F>::construct(config);

        let a = field_chip.load_private(layouter.namespace(|| "load a"), self.a)?;
        let b = field_chip.load_private(layouter.namespace(|| "load b"), self.b)?;

        let constant =
            field_chip.load_constant(layouter.namespace(|| "load constant"), self.constant)?;

        let ab = field_chip.mul(layouter.namespace(|| "a * b"), a, b)?;
        let absq = field_chip.mul(layouter.namespace(|| "ab * ab"), ab.clone(), ab.clone())?;
        let absqsq = field_chip.mul(layouter.namespace(|| "abab * ab"), absq, ab)?;
        let c = field_chip.add(layouter.namespace(|| "constant + absq"), constant, absqsq)?;

        field_chip.expose_public(layouter.namespace(|| "expose c"), c, 0)
    }
}

#[test]
fn test_a_qubed_mul_b_qubed_mocked_prover() {
    let k = 5;

    let constant = Fp::from(7);
    let a = Fp::from(2);
    let b = Fp::from(3);

    // c = constant + a^3 * b^3
    let c = constant + Fp::from(8) * Fp::from(27);

    let circuit = MyCircuit {
        constant,
        a: Value::known(a),
        b: Value::known(b),
    };

    let public_inputs = vec![c];

    let prover = MockProver::run(k, &circuit, vec![public_inputs]).expect("mock proving issue");
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn end_to_end_test_a_qubed_mul_b_qubed() {
    fn test_positive(k: u32, constant: u64, a: u64, b: u64, c: u64, use_circuit_prover: bool) {
        println!("positive_test...");
        assert!(test(k, constant, a, b, c, use_circuit_prover));
        println!("ok");
    }
    fn test_negative(k: u32, constant: u64, a: u64, b: u64, c: u64, use_circuit_prover: bool) {
        println!("negative_test...");
        assert!(!test(k, constant, a, b, c, use_circuit_prover));
        println!("ok");
    }
    fn test(k: u32, constant: u64, a: u64, b: u64, c: u64, use_circuit_prover: bool) -> bool {
        let circuit = MyCircuit::circuit_prover(
            Fp::from(constant),
            Value::known(Fp::from(a)),
            Value::known(Fp::from(b)),
        );

        let public_inputs = circuit.public_inputs(Fp::from(c));

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = MyCircuit::circuit_verifier(Fp::from(constant));
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        };

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

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
        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok()
    }

    let k = 5;

    let constant = Fp::from(7);
    let a = Fp::from(2);
    let b = Fp::from(3);

    // c = constant + a^3 * b^3
    let c = constant + Fp::from(8) * Fp::from(27);

    let circuit = MyCircuit {
        constant,
        a: Value::known(a),
        b: Value::known(b),
    };

    let public_inputs = vec![c];

    let prover = MockProver::run(k, &circuit, vec![public_inputs]).expect("mock proving issue");
    assert_eq!(prover.verify(), Ok(()));

    // Full end-to-end test
    test_positive(k, 7, 2, 3, 7 + 2 * 2 * 2 * 3 * 3 * 3, true);
    test_positive(k, 7, 2, 3, 7 + 2 * 2 * 2 * 3 * 3 * 3, false);
    test_negative(k, 7, 2, 3, 7 + 2 * 2 * 2 * 3 * 3 * 3 + 1, true);
    test_negative(k, 7, 2, 3, 7 + 2 * 2 * 2 * 3 * 3 * 3 + 1, false);
}
