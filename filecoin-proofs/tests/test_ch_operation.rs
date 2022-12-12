use fil_halo2_gadgets::boolean::Bit;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Selector, VirtualCells,
};
use halo2_proofs::poly::Rotation;
use std::ops::{BitAnd, BitXor, Not};

#[test]
fn test_ch_operation() {
    #[derive(Clone)]
    struct ChConfig {
        e: Column<Advice>,
        e_inv: Column<Advice>,
        f: Column<Advice>,
        g: Column<Advice>,
        ch: Column<Advice>,
        s_ch: Selector,
    }

    struct ChChip {
        config: ChConfig,
    }

    impl ChChip {
        fn construct(config: ChConfig) -> Self {
            ChChip { config }
        }
        fn configure(
            meta: &mut ConstraintSystem<Fp>,
            e: Column<Advice>,
            e_inv: Column<Advice>,
            f: Column<Advice>,
            g: Column<Advice>,
            ch: Column<Advice>,
            s_ch: Selector,
        ) -> ChConfig {
            meta.create_gate("ch", |meta: &mut VirtualCells<Fp>| {
                let s_ch = meta.query_selector(s_ch);

                let e = meta.query_advice(e, Rotation::cur());
                let e_inv = meta.query_advice(e_inv, Rotation::cur());
                let f = meta.query_advice(f, Rotation::cur());
                let g = meta.query_advice(g, Rotation::cur());
                let ch = meta.query_advice(ch, Rotation::cur());

                // Jake's: a * (b - c.clone()) - ch + c
                // Alternative: a_inv * b + a * f - ch
                Constraints::with_selector(s_ch, [("ch", e_inv * g + e * f - ch)])
            });

            ChConfig {
                e,
                e_inv,
                f,
                g,
                ch,
                s_ch,
            }
        }

        fn ch(
            &self,
            mut layouter: impl Layouter<Fp>,
            e: Value<bool>,
            f: Value<bool>,
            g: Value<bool>,
        ) -> Result<AssignedCell<Bit, Fp>, Error> {
            layouter.assign_region(
                || "ch",
                |mut region| {
                    self.config.s_ch.enable(&mut region, 0)?;

                    let _ = region.assign_advice(
                        || "e",
                        self.config.e,
                        0,
                        || e.map(|e| Bit::from(e)),
                    )?;

                    let _ = region.assign_advice(
                        || "!e",
                        self.config.e_inv,
                        0,
                        || e.map(|e| Bit::from(!e)),
                    )?;

                    let _ = region.assign_advice(
                        || "f",
                        self.config.f,
                        0,
                        || f.map(|f| Bit::from(f)),
                    )?;

                    let _ = region.assign_advice(
                        || "g",
                        self.config.g,
                        0,
                        || g.map(|g| Bit::from(g)),
                    )?;

                    let ch = e.zip(f).zip(g).map(|((e, f), g)| (e & f) ^ (!e & g));

                    let assigned_ch = region.assign_advice(
                        || "ch",
                        self.config.ch,
                        0,
                        || ch.map(|ch| Bit::from(ch)),
                    )?;

                    Ok(assigned_ch)
                },
            )
        }
    }

    struct TestCircuit {
        e: Value<bool>,
        f: Value<bool>,
        g: Value<bool>,
        expected_ch: Value<bool>,
    }
    impl Circuit<Fp> for TestCircuit {
        type Config = ChConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let s_ch = meta.selector();

            let e = meta.advice_column();
            meta.enable_equality(e);

            let e_inv = meta.advice_column();
            meta.enable_equality(e_inv);

            let f = meta.advice_column();
            meta.enable_equality(f);

            let g = meta.advice_column();
            meta.enable_equality(g);

            let ch = meta.advice_column();
            meta.enable_equality(ch);

            ChChip::configure(meta, e, e_inv, f, g, ch, s_ch)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = ChChip::construct(config);
            let ch = chip.ch(layouter.namespace(|| "ch"), self.e, self.f, self.g)?;

            ch.value()
                .zip(self.expected_ch)
                .map(|(actual, expected)| assert_eq!(bool::from(actual), expected));

            Ok(())
        }
    }

    let circuit = TestCircuit {
        e: Value::known(false),
        f: Value::known(false),
        g: Value::known(false),
        expected_ch: Value::known(false),
    };

    let prover = MockProver::run(4, &circuit, vec![]).expect("couldn't run mock prover");
    assert!(prover.verify().is_ok());
}
