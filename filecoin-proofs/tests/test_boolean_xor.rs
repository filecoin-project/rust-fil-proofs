pub use fil_halo2_gadgets::boolean::and;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{
    AssignedCell, Cell, Chip, Layouter, Region, SimpleFloorPlanner, Value,
};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Constraints, Error, Expression, Instance, Selector, SingleVerifier, VirtualCells,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;
use std::marker::PhantomData;

impl<F: FieldExt> Chip<F> for BooleanXorChip<F> {
    type Config = BooleanXorConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Debug, Clone, Default)]
struct BooleanXorCircuit<F: FieldExt> {
    a: Value<F>,
    b: Value<F>,
}

impl<F: FieldExt> BooleanXorCircuit<F> {
    fn circuit_prover(a: bool, b: bool) -> Self {
        let mut instance = BooleanXorCircuit {
            a: Value::known(F::zero()),
            b: Value::known(F::zero()),
        };
        if a {
            instance.a = Value::known(F::one())
        }
        if b {
            instance.b = Value::known(F::one())
        }
        instance
    }
}

impl<F: FieldExt> Circuit<F> for BooleanXorCircuit<F> {
    type Config = BooleanXorConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    // must return valid configuration
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let a = meta.advice_column();
        //meta.enable_equality(a);

        let b = meta.advice_column();
        //meta.enable_equality(b);

        let xor_result = meta.advice_column();
        meta.enable_equality(xor_result);

        let selector = meta.selector();

        let xor_result_expected = meta.instance_column();
        meta.enable_equality(xor_result_expected);

        meta.create_gate("xor", |meta: &mut VirtualCells<F>| {
            let selector = meta.query_selector(selector);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let out = meta.query_advice(xor_result, Rotation::cur());

            let one_minus_a = Expression::Constant(F::one()) - a.clone();
            let one_minus_b = Expression::Constant(F::one()) - b.clone();

            // XOR(a,b) = (a - AND(a,b) +  b - AND(a,b)
            let a_and_b = and(a.clone(), b.clone());

            Constraints::with_selector(
                selector,
                vec![
                    ("a is boolean", a.clone() * one_minus_a),
                    ("b is boolean", b.clone() * one_minus_b),
                    (
                        "a - a_and_b + b - a_and_b - a_xor_b == 0",
                        a - a_and_b.clone() + b - a_and_b - out,
                    ),
                ]
                .into_iter(),
            )
        });

        BooleanXorConfig {
            a,
            b,
            selector,
            xor_result,
            xor_result_expected,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = BooleanXorChip::<F>::construct(config);

        let assigned_cell = chip.xor(layouter.namespace(|| "xor"), self.a, self.b)?;

        chip.expose_public(layouter, assigned_cell.cell())?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct BooleanXorConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    selector: Selector,
    xor_result: Column<Advice>,
    xor_result_expected: Column<Instance>,
}

#[derive(Debug, Clone)]
struct BooleanXorChip<F: FieldExt> {
    config: BooleanXorConfig,
    _p: PhantomData<F>,
}

impl<F: FieldExt> BooleanXorChip<F> {
    fn construct(config: BooleanXorConfig) -> Self {
        BooleanXorChip {
            config,
            _p: Default::default(),
        }
    }
}

trait Instructions<F: FieldExt> {
    fn xor(
        &self,
        layouter: impl Layouter<F>,
        a: Value<F>,
        b: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error>;
    fn expose_public(&self, layouter: impl Layouter<F>, cell: Cell) -> Result<(), Error>;
}

impl<F: FieldExt> Instructions<F> for BooleanXorChip<F> {
    fn xor(
        &self,
        mut layouter: impl Layouter<F>,
        a: Value<F>,
        b: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "xor",
            |mut region: Region<F>| {
                // enable selector for the XOR gate
                self.config.selector.enable(&mut region, 0)?;

                // assign a into advice column
                let a = region.assign_advice(|| "a", self.config.a, 0, || a)?;

                // assign b into advice column
                let b = region.assign_advice(|| "a", self.config.b, 0, || b)?;

                // compute actual value...
                let xor_result = a.value().zip(b.value()).map(|(a, b)| {
                    if *a == *b { F::zero() } else { F::one() }
                });

                // and assign it into separate advice column
                region.assign_advice(|| "xor", self.config.xor_result, 0, || xor_result)
            },
        )
    }

    fn expose_public(&self, mut layouter: impl Layouter<F>, cell: Cell) -> Result<(), Error> {
        // we expect some value provided as a public input to compare with computed xor result in the instance column
        layouter.constrain_instance(cell, self.config.xor_result_expected, 0)
    }
}

#[test]
fn test_boolean_xor_mock_prover() {
    fn test(a: bool, b: bool, c: bool) {
        let circuit = BooleanXorCircuit::circuit_prover(a, b);

        let public_inputs = if c { vec![Fp::one()] } else { vec![Fp::zero()] };

        let k = 3;

        let prover = MockProver::run(k, &circuit, vec![public_inputs])
            .expect("couldn't run mock prover");
        prover.verify().expect("verification error");
    }

    let a = false;
    let b = false;
    let c = false;
    test(a, b, c);

    let a = true;
    let b = false;
    let c = true;
    test(a, b, c);

    let a = false;
    let b = true;
    let c = true;
    test(a, b, c);

    let a = true;
    let b = true;
    let c = false;
    test(a, b, c);
}

#[test]
fn test_boolean_xor_end_to_end() {
    fn test(a: bool, b: bool, c: bool, use_circuit_prover_for_keygen: bool) -> bool {
        let circuit = BooleanXorCircuit::circuit_prover(a, b);

        let public_inputs = if c { vec![Fp::one()] } else { vec![Fp::zero()] };

        let k = 3;

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover_for_keygen {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = BooleanXorCircuit::default();
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

    fn negative_test(a: bool, b: bool, c: bool, use_circuit_prover_for_keygen: bool) {
        assert!(!test(a, b, c, use_circuit_prover_for_keygen));
    }

    fn positive_test(a: bool, b: bool, c: bool, use_circuit_prover_for_keygen: bool) {
        assert!(test(a, b, c, use_circuit_prover_for_keygen));
    }

    let a = false;
    let b = false;
    let c = false;
    positive_test(a, b, c, true);
    positive_test(a, b, c, false);
    negative_test(a, !b, c, true);

    let a = true;
    let b = false;
    let c = true;
    positive_test(a, b, c, true);
    positive_test(a, b, c, false);
    negative_test(a, !b, c, true);

    let a = false;
    let b = true;
    let c = true;
    positive_test(a, b, c, true);
    positive_test(a, b, c, false);
    negative_test(a, !b, c, true);

    let a = true;
    let b = true;
    let c = false;
    positive_test(a, b, c, true);
    positive_test(a, b, c, false);
    negative_test(a, !b, c, true);
}
