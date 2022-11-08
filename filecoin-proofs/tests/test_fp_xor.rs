use ff::{Field, PrimeField};
use fil_halo2_gadgets::boolean::{lebs2ip, Bit, LeBitsChip, LeBitsConfig, WINDOW_BITS};
use halo2_gadgets::utilities::bool_check;
use halo2_proofs::circuit::{AssignedCell, Cell, Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Constraints, Error, Instance, Selector, SingleVerifier, VirtualCells,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;
use std::convert::TryInto;

struct BooleanXorChip {
    config: BooleanXorConfig,
}

impl BooleanXorChip {
    fn construct(config: BooleanXorConfig) -> Self {
        BooleanXorChip { config }
    }
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        a: Column<Advice>,
        b: Column<Advice>,
        xor_result: Column<Advice>,
        xor_result_pi: Column<Instance>,
        selector: Selector,
    ) -> BooleanXorConfig {
        meta.enable_equality(xor_result);
        meta.enable_equality(xor_result_pi);

        meta.create_gate("xor", |meta: &mut VirtualCells<Fp>| {
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
                        "Bitwise XOR: a - a_and_b + b - a_and_b - a_xor_b == 0",
                        (a.clone() + a.clone()) * b.clone() - a - b + out,
                    ),
                ]
                .into_iter(),
            )
        });

        BooleanXorConfig {
            a,
            b,
            xor_result,
            xor_result_pi,
            selector,
        }
    }
}

trait Instructions {
    fn xor(
        &self,
        layouter: impl Layouter<Fp>,
        a: Value<Bit>,
        b: Value<Bit>,
        advice_offset: usize,
    ) -> Result<AssignedCell<Bit, Fp>, Error>;
    fn expose_public(
        &self,
        layouter: impl Layouter<Fp>,
        cell: Cell,
        instance_offset: usize,
    ) -> Result<(), Error>;
}

impl Instructions for BooleanXorChip {
    fn xor(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Bit>,
        b: Value<Bit>,
        advice_offset: usize,
    ) -> Result<AssignedCell<Bit, Fp>, Error> {
        layouter.assign_region(
            || "xor",
            |mut region: Region<Fp>| {
                // enable selector for the XOR gate
                self.config.selector.enable(&mut region, advice_offset)?;

                // assign a into advice column
                let a = region.assign_advice(|| "a", self.config.a, advice_offset, || a)?;

                // assign b into advice column
                let b = region.assign_advice(|| "a", self.config.b, advice_offset, || b)?;

                // compute actual value...
                let xor_result = a
                    .value()
                    .zip(b.value())
                    .map(|(a, b)| Bit(bool::from(a) ^ bool::from(b)));

                // and assign it into separate advice column
                region.assign_advice(
                    || "xor",
                    self.config.xor_result,
                    advice_offset,
                    || xor_result,
                )
            },
        )
    }

    fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: Cell,
        instance_offset: usize,
    ) -> Result<(), Error> {
        // we expect some value provided as a public input to compare with computed xor result in the instance column
        layouter.constrain_instance(cell, self.config.xor_result_pi, instance_offset)
    }
}

#[derive(Default)]
struct FpXorCircuit {
    a: Value<Fp>,
    b: Value<Fp>,
}

#[derive(Debug, Clone)]
struct BooleanXorConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    selector: Selector,
    xor_result: Column<Advice>,
    xor_result_pi: Column<Instance>,
}

impl FpXorCircuit {
    fn k(&self) -> u32 {
        15 + 1 // defined empirically
    }
    fn public_input(&self, xor_result: Fp) -> Vec<Fp> {
        vec![xor_result]
    }
}

impl Circuit<Fp> for FpXorCircuit {
    type Config = (LeBitsConfig<Fp>, BooleanXorConfig);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        FpXorCircuit {
            a: Value::unknown(),
            b: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice: [Column<Advice>; 1 + WINDOW_BITS] = (0..1 + WINDOW_BITS)
            .map(|_| meta.advice_column())
            .collect::<Vec<Column<Advice>>>()
            .try_into()
            .unwrap();
        let le_bits_config = LeBitsChip::configure(meta, advice);

        let a = meta.advice_column();
        let b = meta.advice_column();
        let xor_result = meta.advice_column();
        let xor_result_pi = meta.instance_column();
        let selector = meta.selector();

        let boolean_xor_config =
            BooleanXorChip::configure(meta, a, b, xor_result, xor_result_pi, selector);

        (le_bits_config, boolean_xor_config)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Assign `self.value` in the first advice column because that column is equality
        // constrained by the running sum chip.
        let value_col = config.0.advice[0];

        let le_bits_chip = LeBitsChip::construct(config.0);
        let xor_chip = BooleanXorChip::construct(config.1);

        let bits1 = layouter
            .assign_region(
                || "decompose1",
                |mut region| {
                    let mut offset = 0;
                    let value = region.assign_advice(|| "value", value_col, offset, || self.a)?;
                    offset += 1;
                    le_bits_chip.copy_decompose_within_region(&mut region, offset, value)
                },
            )?
            .into_iter()
            .map(|asn| asn.value().map(Into::into));

        let bits2 = layouter
            .assign_region(
                || "decompose2",
                |mut region| {
                    let mut offset = 0;
                    let value = region.assign_advice(|| "value", value_col, offset, || self.b)?;
                    offset += 1;

                    le_bits_chip.copy_decompose_within_region(&mut region, offset, value)
                },
            )?
            .into_iter()
            .map(|asn| asn.value().map(Into::into));

        #[allow(clippy::needless_collect)]
        // execute bitwise xoring of our values decomposed previously
        let values: Vec<AssignedCell<Bit, Fp>> = bits1
            .zip(bits2)
            .enumerate()
            .map(
                |(index, (bit1, bit2)): (usize, (Value<bool>, Value<bool>))| {
                    let bit1 = bit1.map(Bit::from);
                    let bit2 = bit2.map(Bit::from);

                    // xor bit1, bit2
                    let xor_result = xor_chip
                        .xor(
                            layouter.namespace(|| format!("xor {}", index)),
                            bit1,
                            bit2,
                            index,
                        )
                        .expect("couldn't perform single XOR operation");

                    xor_result
                },
            )
            .collect::<Vec<AssignedCell<Bit, Fp>>>();

        // for convenience let's compose 255 Fps (1 or 0) into single Fp
        let chunks_iter = values.chunks(64);
        let limbs = chunks_iter
            .map(|limb_slice| {
                let mut bits = limb_slice
                    .iter()
                    .map(|limb_value_bit| {
                        let mut bit = false;
                        limb_value_bit.value().map(|limb_value_bit| {
                            if limb_value_bit.0 {
                                bit = true;
                            }
                        });
                        bit
                    })
                    .collect::<Vec<bool>>();
                // final chunk contains less than 64 bits as Fp contains 255 bits total
                if bits.len() < 64 {
                    bits.append(&mut vec![false; 64 - bits.len()])
                }
                lebs2ip::<64>(&bits.try_into().unwrap())
            })
            .collect::<Vec<u64>>();

        let fp_composed = Fp::from_raw(limbs.try_into().unwrap());

        // expose single composed Fp which holds XOR result
        let cell = layouter.assign_region(
            || "assign xor result",
            |mut region| {
                let cell = region.assign_advice(
                    || "value",
                    xor_chip.config.xor_result,
                    255,
                    || Value::known(fp_composed),
                );
                cell
            },
        )?;

        xor_chip
            .expose_public(
                layouter.namespace(|| "exposing xor result as a field element"),
                cell.cell(),
                0,
            )
            .expect("couldn't expose xor field element");

        Ok(())
    }
}

#[test]
fn test_fp_xor_mocked_prover() {
    let a: u64 = 50;
    let b: u64 = 27;
    let c: u64 = 50 ^ 27;

    let circuit = FpXorCircuit {
        a: Value::known(Fp::from(a)),
        b: Value::known(Fp::from(b)),
    };

    let public_input = circuit.public_input(Fp::from(c));

    let prover = MockProver::run(circuit.k(), &circuit, vec![public_input])
        .expect("can't run mocked prover");

    assert!(prover.verify().is_ok());
}

#[test]
fn test_fp_xor_end_to_end() {
    fn test(a: Fp, b: Fp, c: Fp, use_circuit_prover_for_keygen: bool) -> bool {
        let circuit = FpXorCircuit {
            a: Value::known(a),
            b: Value::known(b),
        };

        let public_inputs = circuit.public_input(c);

        let k = circuit.k();

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover_for_keygen {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = FpXorCircuit::default();
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

        let result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok();

        result
    }

    fn negative_test(a: Fp, b: Fp, c: Fp, use_circuit_prover_for_keygen: bool) {
        println!("negative test ...");
        assert!(!test(a, b, c, use_circuit_prover_for_keygen));
        println!("OK");
    }

    fn positive_test(a: Fp, b: Fp, c: Fp, use_circuit_prover_for_keygen: bool) {
        println!("positive test ...");
        assert!(test(a, b, c, use_circuit_prover_for_keygen));
        println!("OK");
    }

    let a = Fp::from(50);
    let b = Fp::from(27);
    let c = Fp::from(50 ^ 27);
    positive_test(a, b, c, true);
    positive_test(a, b, c, false);
    negative_test(a, b + Fp::one(), c, true);

    let a = Fp::random(OsRng);
    let b = Fp::random(OsRng);
    let c = fp_xor(a, b);

    positive_test(a, b, c, true);
    positive_test(a, b, c, false);
    negative_test(a, b + Fp::one(), c, true);
}

fn fp_xor(a: Fp, b: Fp) -> Fp {
    let xor = a
        .to_repr()
        .iter()
        .zip(b.to_repr().iter())
        .map(|(byte1, byte2)| *byte1 ^ *byte2)
        .collect::<Vec<u8>>();
    Fp::from_repr(xor.try_into().unwrap()).unwrap()
}
