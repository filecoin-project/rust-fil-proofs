use fil_halo2_gadgets::boolean::Bit;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Selector,
    VirtualCells,
};
use halo2_proofs::poly::Rotation;

#[test]
fn test_maj_debug() {
    let a = true;
    let b = false;
    let c = false;
    let maj = (a & b) ^ (a & c) ^ (b & c);

    let a = if a { 1u32 } else { 0u32 };
    let b = if b { 1u32 } else { 0u32 };
    let c = if c { 1u32 } else { 0u32 };
    let a_not: u32 = if a == 1 { 0 } else { 1 };
    let b_not: u32 = if b == 1 { 0 } else { 1 };

    let maj_alt = c + a * b - a_not * b_not * c - a * b * c;

    println!("maj: {} {}", maj, maj_alt);
    assert_eq!(maj, if maj_alt == 0 { false } else { true })
}

#[test]
fn test_maj_operation() {
    struct MajChip {
        config: MajConfig,
    }

    impl MajChip {
        fn configure(
            meta: &mut ConstraintSystem<Fp>,
            a: Column<Advice>,
            a_inv: Column<Advice>,
            b: Column<Advice>,
            b_inv: Column<Advice>,
            c: Column<Advice>,
            maj: Column<Advice>,
            s_maj: Selector,
        ) -> MajConfig {
            meta.create_gate("maj", |meta: &mut VirtualCells<Fp>| {
                let s_maj = meta.query_selector(s_maj);

                let a = meta.query_advice(a, Rotation::cur());

                let a_inv = meta.query_advice(a_inv, Rotation::cur());

                let b = meta.query_advice(b, Rotation::cur());

                let b_inv = meta.query_advice(b_inv, Rotation::cur());

                let c = meta.query_advice(c, Rotation::cur());

                let maj = meta.query_advice(maj, Rotation::cur());

                let a_b = a * b;

                // Jake's: (2bc - b - c)a = bc - maj
                // Alternative: ab + c * (1 - a_inv * b_inv - ab) - maj
                Constraints::with_selector(
                    s_maj,
                    [(
                        "maj bit",
                        a_b.clone() + c * (Expression::Constant(Fp::one()) - a_inv * b_inv - a_b)
                            - maj,
                    )],
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
            }
        }
        fn construct(config: MajConfig) -> MajChip {
            MajChip { config }
        }
        fn maj(
            &self,
            mut layouter: impl Layouter<Fp>,
            a: Value<Bit>,
            b: Value<Bit>,
            c: Value<Bit>,
        ) -> Result<AssignedCell<Bit, Fp>, Error> {
            layouter.assign_region(
                || "maj",
                |mut region| {
                    self.config.s_maj.enable(&mut region, 0)?;

                    region.assign_advice(|| "a", self.config.a, 0, || a)?;

                    let a_inv = a.map(|a| Bit(!bool::from(a)));

                    region.assign_advice(|| "a_inv", self.config.a_inv, 0, || a_inv)?;

                    region.assign_advice(|| "b", self.config.b, 0, || b)?;

                    let b_inv = b.map(|b| Bit(!bool::from(b)));

                    region.assign_advice(|| "b_inv", self.config.b_inv, 0, || b_inv)?;

                    region.assign_advice(|| "c", self.config.c, 0, || c)?;

                    let maj_computed = a.zip(b).zip(c).map(|((a, b), c)| {
                        let a = bool::from(a);
                        let b = bool::from(b);
                        let c = bool::from(c);
                        Bit((a & b) ^ (a & c) ^ (b & c))
                    });

                    region.assign_advice(|| "maj", self.config.maj, 0, || maj_computed)
                },
            )
        }
    }

    #[derive(Clone)]
    struct MajConfig {
        a: Column<Advice>,
        a_inv: Column<Advice>,
        b: Column<Advice>,
        b_inv: Column<Advice>,
        c: Column<Advice>,
        maj: Column<Advice>,
        s_maj: Selector,
    }

    struct TestCircuit {
        a: Value<Bit>,
        b: Value<Bit>,
        c: Value<Bit>,
        expected_maj: Value<Bit>,
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = MajConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            TestCircuit {
                a: Value::unknown(),
                b: Value::unknown(),
                c: Value::unknown(),
                expected_maj: Value::unknown(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let a = meta.advice_column();
            meta.enable_equality(a);
            let b = meta.advice_column();
            meta.enable_equality(b);
            let c = meta.advice_column();
            meta.enable_equality(c);
            let a_inv = meta.advice_column();
            meta.enable_equality(a_inv);
            let b_inv = meta.advice_column();
            meta.enable_equality(b_inv);
            let maj = meta.advice_column();
            meta.enable_equality(maj);

            let s_maj = meta.selector();

            MajChip::configure(meta, a, a_inv, b, b_inv, c, maj, s_maj)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = MajChip::construct(config);

            let computed = chip.maj(layouter.namespace(|| "maj"), self.a, self.b, self.c)?;

            computed
                .value()
                .zip(self.expected_maj)
                .map(|(actual, expected)| assert_eq!(bool::from(*actual), bool::from(expected)));

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
            a: Value::known(Bit::from(test_input.0)),
            b: Value::known(Bit::from(test_input.1)),
            c: Value::known(Bit::from(test_input.2)),
            expected_maj: Value::known(Bit::from(test_input.3)),
        };

        let prover = MockProver::run(3, &circuit, vec![]).expect("couldn't run mock prover");
        assert!(prover.verify().is_ok());
    }
}
