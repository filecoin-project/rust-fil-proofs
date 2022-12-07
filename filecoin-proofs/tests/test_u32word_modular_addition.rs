use ff::PrimeFieldBits;
use halo2_gadgets::utilities::decompose_running_sum::{RunningSum, RunningSumConfig};
use halo2_proofs::circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

const WORD_BIT_LENGTH: usize = 32;
const WINDOW_BIT_LENGTH: usize = 2;
const NUM_WINDOWS: usize = (WORD_BIT_LENGTH + WINDOW_BIT_LENGTH - 1) / WINDOW_BIT_LENGTH;

#[derive(Clone)]
struct U32WordModularAddConfig {
    running_sum: RunningSumConfig<Fp, WINDOW_BIT_LENGTH>,
    a: Column<Advice>,
    b: Column<Advice>,
    c_lo: Column<Advice>,
    c_hi: Column<Advice>,
    s_mod_add2: Selector,
    s_mod_add4: Selector,
}

struct U32WordModularAddChip {
    config: U32WordModularAddConfig,
}

impl U32WordModularAddChip {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        z: Column<Advice>,
        q_range_check: Selector,
        a: Column<Advice>,
        b: Column<Advice>,
        s_mod_add2: Selector,
        s_mod_add4: Selector,
        c_lo: Column<Advice>,
        c_hi: Column<Advice>,
    ) -> U32WordModularAddConfig {
        let running_sum =
            RunningSumConfig::<Fp, WINDOW_BIT_LENGTH>::configure(meta, q_range_check, z);

        meta.create_gate("modular add2", |meta| {
            let selector = meta.query_selector(s_mod_add2);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c_lo = meta.query_advice(c_lo, Rotation::cur());
            let c_hi = meta.query_advice(c_hi, Rotation::cur());

            let c = c_lo + (Expression::Constant(Fp::from(1u64 << 32)) * c_hi);
            [("modular addition2", selector * (a + b - c))]
        });

        meta.create_gate("modular add4", |meta| {
            let selector = meta.query_selector(s_mod_add4);
            let a_val = meta.query_advice(a, Rotation::cur());
            let b_val = meta.query_advice(a, Rotation::next());
            let c_val = meta.query_advice(b, Rotation::cur());
            let d_val = meta.query_advice(b, Rotation::next());

            let c_lo = meta.query_advice(c_lo, Rotation::cur());
            let c_hi = meta.query_advice(c_hi, Rotation::cur());

            let c = c_lo + (Expression::Constant(Fp::from(1u64 << 32)) * c_hi);
            [(
                "modular addition4",
                selector * (a_val + b_val + c_val + d_val - c),
            )]
        });

        U32WordModularAddConfig {
            running_sum,
            a,
            b,
            c_lo,
            c_hi,
            s_mod_add2,
            s_mod_add4,
        }
    }

    fn construct(config: U32WordModularAddConfig) -> Self {
        U32WordModularAddChip { config }
    }

    fn witness_decompose(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        alpha: Value<Fp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum<Fp>, Error> {
        self.config.running_sum.witness_decompose(
            region,
            offset,
            alpha,
            strict,
            word_num_bits,
            num_windows,
        )
    }

    fn copy_decompose(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        alpha: AssignedCell<Fp, Fp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum<Fp>, Error> {
        self.config.running_sum.copy_decompose(
            region,
            offset,
            alpha,
            strict,
            word_num_bits,
            num_windows,
        )
    }

    fn range_check(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "range check",
            |mut region| {
                let offset = 0;
                let zs = self.witness_decompose(
                    &mut region,
                    offset,
                    a,
                    true,
                    WORD_BIT_LENGTH,
                    NUM_WINDOWS,
                )?;

                let b = zs[0].clone();

                let offset = offset + NUM_WINDOWS + 1;

                let running_sum = self.copy_decompose(
                    &mut region,
                    offset,
                    b,
                    true,
                    WORD_BIT_LENGTH,
                    NUM_WINDOWS,
                )?;

                Ok(running_sum[0].clone())
            },
        )
    }

    fn modular_add4(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
        c: AssignedCell<Fp, Fp>,
        d: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "modular addition",
            |mut region| {
                self.config.s_mod_add4.enable(&mut region, 0)?;

                let a = a.copy_advice(|| "a copy", &mut region, self.config.a, 0)?;
                let b = b.copy_advice(|| "b copy", &mut region, self.config.a, 1)?;
                let c = c.copy_advice(|| "c copy", &mut region, self.config.b, 0)?;
                let d = d.copy_advice(|| "d copy", &mut region, self.config.b, 1)?;

                fn u32_plus_u32(a: Value<Fp>, b: Value<Fp>) -> (Value<Fp>, Value<Fp>) {
                    a.zip(b)
                        .map(|(a, b)| {
                            let lhs = a
                                .to_le_bits()
                                .iter()
                                .enumerate()
                                .fold(0u64, |acc, (i, bit)| acc + ((*bit as u64) << i));
                            let rhs = b
                                .to_le_bits()
                                .iter()
                                .enumerate()
                                .fold(0u64, |acc, (i, bit)| acc + ((*bit as u64) << i));

                            let sum = lhs + rhs;
                            let sum_lo = sum & u32::MAX as u64;
                            let sum_hi = sum >> 32;

                            (Fp::from(sum_lo), Fp::from(sum_hi))
                        })
                        .unzip()
                }

                let (one_lo, one_hi) = u32_plus_u32(a.value().map(|a| *a), b.value().map(|b| *b));

                let (two_lo, two_hi) = u32_plus_u32(c.value().map(|c| *c), d.value().map(|d| *d));

                let (three_lo, three_hi) = u32_plus_u32(one_lo, two_lo);

                // if a + b + c + d overflows, it will be > 0, otherwise - 0. Gate definition relies on this information
                region.assign_advice(
                    || "sum_hi",
                    self.config.c_hi,
                    0,
                    || one_hi + two_hi + three_hi,
                )?;

                // output low part of result
                region.assign_advice(|| "sum_lo", self.config.c_lo, 0, || three_lo)
            },
        )
    }

    fn modular_add2(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "modular addition",
            |mut region| {
                self.config.s_mod_add2.enable(&mut region, 0)?;

                let a = a.copy_advice(|| "a copy", &mut region, self.config.a, 0)?;

                let b = b.copy_advice(|| "b copy", &mut region, self.config.b, 0)?;

                let c = a
                    .value()
                    .zip(b.value())
                    .map(|(a, b)| {
                        let lhs = a
                            .to_le_bits()
                            .iter()
                            .enumerate()
                            .fold(0u64, |acc, (i, bit)| acc + ((*bit as u64) << i));
                        let rhs = b
                            .to_le_bits()
                            .iter()
                            .enumerate()
                            .fold(0u64, |acc, (i, bit)| acc + ((*bit as u64) << i));

                        let sum = lhs + rhs;
                        let sum_lo = sum & u32::MAX as u64;
                        let sum_hi = sum >> 32;

                        (Fp::from(sum_lo), Fp::from(sum_hi))
                    })
                    .unzip();

                // if a + b overflows, it will be 1, otherwise - 0. Gate definition relies on this information
                region.assign_advice(|| "sum_hi", self.config.c_hi, 0, || c.1)?;

                // output low part of result
                region.assign_advice(|| "sum_lo", self.config.c_lo, 0, || c.0)
            },
        )
    }
}

#[test]
fn test_u32word_modular_addition_mocked_prover() {
    struct TestCircuit {
        a: Value<Fp>,
        b: Value<Fp>,
        a_plus_b: Value<Fp>,
        a_plus_b_b_b: Value<Fp>,
    }

    impl TestCircuit {
        fn k(&self) -> u32 {
            8
        }
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = U32WordModularAddConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            // running_sum requires this
            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let selector = meta.selector();
            let q_range_check = meta.advice_column();

            let a = meta.advice_column();
            let b = meta.advice_column();
            let c_lo = meta.advice_column();
            let c_hi = meta.advice_column();
            let s_modular_add2 = meta.selector();
            let s_modular_add4 = meta.selector();

            meta.enable_equality(q_range_check);
            meta.enable_equality(a);
            meta.enable_equality(b);
            meta.enable_equality(c_lo);
            meta.enable_equality(c_hi);

            U32WordModularAddChip::configure(
                meta,
                q_range_check,
                selector,
                a,
                b,
                s_modular_add2,
                s_modular_add4,
                c_lo,
                c_hi,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = U32WordModularAddChip::construct(config);

            // range check that both a and b are u32 words
            let assigned_fp_a =
                chip.range_check(layouter.namespace(|| "range check of a"), self.a)?;

            let assigned_fp_b =
                chip.range_check(layouter.namespace(|| "range check of b"), self.b)?;

            let result = chip.modular_add2(
                layouter.namespace(|| "modular addition2"),
                assigned_fp_a,
                assigned_fp_b,
            )?;

            self.a_plus_b
                .zip(result.value())
                .map(|(expected, actual)| assert_eq!(expected, *actual));

            let assigned_fp_a =
                chip.range_check(layouter.namespace(|| "range check of a"), self.a)?;

            let assigned_fp_b =
                chip.range_check(layouter.namespace(|| "range check of b"), self.b)?;

            let assigned_fp_c =
                chip.range_check(layouter.namespace(|| "range check of c"), self.b)?;

            let assigned_fp_d =
                chip.range_check(layouter.namespace(|| "range check of d"), self.b)?;

            let result = chip.modular_add4(
                layouter.namespace(|| "modular addition4"),
                assigned_fp_a,
                assigned_fp_b,
                assigned_fp_c,
                assigned_fp_d,
            )?;

            self.a_plus_b_b_b
                .zip(result.value())
                .map(|(expected, actual)| assert_eq!(expected, *actual));

            Ok(())
        }
    }

    let circuit = TestCircuit {
        a: Value::known(Fp::from(u32::MAX as u64)),
        b: Value::known(Fp::from(u32::MAX as u64)),
        a_plus_b: Value::known(Fp::from(4294967294)),
        a_plus_b_b_b: Value::known(Fp::from(4294967292)),
    };

    let prover = MockProver::run(circuit.k(), &circuit, vec![]).expect("couldn't run mock prover");
    assert!(prover.verify().is_ok());

    let circuit = TestCircuit {
        a: Value::known(Fp::from(50)),
        b: Value::known(Fp::from(100)),
        a_plus_b: Value::known(Fp::from(150)),
        a_plus_b_b_b: Value::known(Fp::from(350)),
    };

    let prover = MockProver::run(circuit.k(), &circuit, vec![]).expect("couldn't run mock prover");
    assert!(prover.verify().is_ok());
}
