pub use fil_halo2_gadgets::boolean::and;
use fil_halo2_gadgets::boolean::Bit;
use halo2_gadgets::utilities::bool_check;
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

const PI_ROW: usize = 0;

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
struct BooleanXorCircuit {
    a: Value<Bit>,
    b: Value<Bit>,
}

impl BooleanXorCircuit {
    fn circuit_prover(a: bool, b: bool) -> Self {
        BooleanXorCircuit {
            a: Value::known(Bit::from(a)),
            b: Value::known(Bit::from(b)),
        }
    }
}

impl<F: FieldExt> Circuit<F> for BooleanXorCircuit {
    type Config = BooleanXorConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    // must return valid configuration
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let a = meta.advice_column();

        let b = meta.advice_column();

        let xor_result = meta.advice_column();

        let xor_result_expected = meta.instance_column();

        let selector = meta.selector();

        BooleanXorChip::configure(meta, a, b, xor_result, xor_result_expected, selector);

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

        chip.expose_public(layouter, assigned_cell.cell())
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

    fn configure(
        meta: &mut ConstraintSystem<F>,
        a: Column<Advice>,
        b: Column<Advice>,
        xor_result: Column<Advice>,
        xor_result_pi: Column<Instance>,
        selector: Selector,
    ) {
        meta.enable_equality(xor_result);
        meta.enable_equality(xor_result_pi);

        meta.create_gate("xor", |meta: &mut VirtualCells<F>| {
            let selector = meta.query_selector(selector);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let out = meta.query_advice(xor_result, Rotation::cur());

            Constraints::with_selector(
                selector,
                vec![
                    ("a is boolean", bool_check(a.clone())),
                    ("b is boolean", bool_check(b.clone())),
                    (
                        "a - a_and_b + b - a_and_b - a_xor_b == 0",
                        (a.clone() + a.clone()) * b.clone() - a - b + out,
                    ),
                ]
                .into_iter(),
            )
        });
    }
}

trait Instructions<F: FieldExt> {
    fn xor(
        &self,
        layouter: impl Layouter<F>,
        a: Value<Bit>,
        b: Value<Bit>,
    ) -> Result<AssignedCell<Bit, F>, Error>;
    fn expose_public(&self, layouter: impl Layouter<F>, cell: Cell) -> Result<(), Error>;
}

impl<F: FieldExt> Instructions<F> for BooleanXorChip<F> {
    fn xor(
        &self,
        mut layouter: impl Layouter<F>,
        a: Value<Bit>,
        b: Value<Bit>,
    ) -> Result<AssignedCell<Bit, F>, Error> {
        layouter.assign_region(
            || "xor",
            |mut region: Region<F>| {
                // enable selector for the XOR gate
                self.config.selector.enable(&mut region, 0)?;

                // assign a into advice column
                let a = region.assign_advice(|| "a", self.config.a, 0, || a)?;

                // assign b into advice column
                let b = region.assign_advice(|| "a", self.config.b, 0, || b)?;

                // and assign it into separate advice column
                region.assign_advice(
                    || "xor",
                    self.config.xor_result,
                    0,
                    || {
                        a.value()
                            .zip(b.value())
                            .map(|(a, b)| Bit(bool::from(a) ^ bool::from(b)))
                    },
                )
            },
        )
    }

    fn expose_public(&self, mut layouter: impl Layouter<F>, cell: Cell) -> Result<(), Error> {
        // we expect some value provided as a public input to compare with computed xor result in the instance column
        layouter.constrain_instance(cell, self.config.xor_result_expected, PI_ROW)
    }
}

#[test]
fn test_boolean_xor_mock_prover() {
    fn test(a: bool, b: bool, c: bool) {
        let circuit = BooleanXorCircuit::circuit_prover(a, b);

        let public_inputs = if c { vec![Fp::one()] } else { vec![Fp::zero()] };

        let k = 3;

        let prover =
            MockProver::run(k, &circuit, vec![public_inputs]).expect("couldn't run mock prover");
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
