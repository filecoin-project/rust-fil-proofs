use std::convert::TryInto;
use std::marker::PhantomData;

use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Instance, Selector},
    poly::Rotation,
};

use crate::{
    boolean::{AssignedBit, AssignedBits, Bit},
    NumCols,
};

pub const NUM_ADVICE_EQ: usize = 9;

pub const U32_DECOMP_NUM_COLS: NumCols = NumCols {
    advice_eq: 9,
    advice_neq: 0,
    fixed_eq: 0,
    fixed_neq: 0,
};

pub type AssignedU32<F> = AssignedBits<F, 32>;

#[derive(Clone, Debug)]
pub struct U32DecompConfig<F: FieldExt> {
    pub(crate) value: Column<Advice>,
    pub(crate) limbs: [Column<Advice>; 8],
    pub(crate) s_field_into_u32s: Selector,
    pub(crate) s_u32_into_bits: Option<Selector>,
    pub(crate) _f: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct U32DecompChip<F: FieldExt> {
    config: U32DecompConfig<F>,
}

impl<F: FieldExt> U32DecompChip<F> {
    pub fn construct(config: U32DecompConfig<F>) -> Self {
        U32DecompChip { config }
    }

    // # Side Effects
    //
    // All `advice` columns will be equality constrained.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 9],
    ) -> U32DecompConfig<F> {
        Self::configure_inner(meta, advice, false)
    }

    pub fn configure_with_binary_decomp(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 9],
    ) -> U32DecompConfig<F> {
        Self::configure_inner(meta, advice, true)
    }

    fn configure_inner(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 9],
        binary_decomp: bool,
    ) -> U32DecompConfig<F> {
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let value = advice[0];
        let limbs: [Column<Advice>; 8] = advice[1..].try_into().unwrap();

        let s_field_into_u32s = meta.selector();

        let mut powers_of_u32_radix = Vec::with_capacity(7);
        let radix = F::from(1 << 32);
        powers_of_u32_radix.push(radix);
        for i in 0..6 {
            powers_of_u32_radix.push(powers_of_u32_radix[i] * radix);
        }

        meta.create_gate("field_into_u32s", |meta| {
            let s = meta.query_selector(s_field_into_u32s);
            let value = meta.query_advice(value, Rotation::cur());
            let limb_0 = meta.query_advice(limbs[0], Rotation::cur());
            let expr = limbs[1..].iter().zip(powers_of_u32_radix.iter()).fold(
                limb_0,
                |acc, (col, coeff)| {
                    let limb = meta.query_advice(*col, Rotation::cur());
                    acc + Expression::Constant(*coeff) * limb
                },
            );
            vec![s * (expr - value)]
        });

        let s_u32_into_bits = if binary_decomp {
            let s_u32_into_bits = meta.selector();

            let mut powers_of_two = Vec::with_capacity(31);
            let radix = F::from(2);
            powers_of_two.push(radix);
            for i in 0..30 {
                powers_of_two.push(powers_of_two[i] * radix);
            }

            meta.create_gate("u32_into_bits", |meta| {
                let s = meta.query_selector(s_u32_into_bits);
                let value = meta.query_advice(value, Rotation::cur());

                let mut bits: Vec<Expression<F>> = Vec::with_capacity(32);
                for byte_index in 0..4 {
                    let offset = Rotation(byte_index as i32);
                    for col in limbs.iter() {
                        bits.push(meta.query_advice(*col, offset));
                    }
                }

                let mut constraints = Vec::with_capacity(33);
                for bit in bits.iter() {
                    constraints.push(s.clone() * bool_check(bit.clone()));
                }
                let mut bits = bits.into_iter();
                let mut expr = bits.next().unwrap();
                for (bit, coeff) in bits.zip(powers_of_two.iter()) {
                    expr = expr + Expression::Constant(*coeff) * bit;
                }
                constraints.push(s * (expr - value));
                constraints
            });

            Some(s_u32_into_bits)
        } else {
            None
        };

        U32DecompConfig {
            value,
            limbs,
            s_field_into_u32s,
            s_u32_into_bits,
            _f: PhantomData,
        }
    }

    // | ----- | ------ | ------ | --- | ------ | ----------------- | --------------- |
    // |  a_1  |  a_2   |  a_3   | ... |  a_9   | s_field_into_u32s | s_u32_into_bits |
    // | ----- | ------ | ------ | --- | ------ | ----------------- | --------------- |
    // |  val  | u32_1  | u32_2  | ... | u32_8  |         1         |        0        |
    // | u32_1 | bit_1  | bit_2  | ... | bit_8  |         0         |        1        |
    // |       | bit_9  | bit_10 | ... | bit_16 |         0         |        0        |
    // |       | bit_17 | bit_18 | ... | bit_24 |         0         |        0        |
    // |       | bit_25 | bit_26 | ... | bit_32 |         0         |        0        |
    // | u32_2 | bit_1  | bit_2  | ... | bit_8  |         0         |        1        |
    // |       |  ...   |  ...   | ... |  ...   |        ...        |       ...       |
    // | u32_8 | bit_1  | bit_2  | ... | bit_8  |         0         |        1        |
    // |       | bit_9  | bit_10 | ... | bit_16 |         0         |        0        |
    // |       | bit_17 | bit_18 | ... | bit_24 |         0         |        0        |
    // |       | bit_25 | bit_26 | ... | bit_32 |         0         |        0        |
    pub fn witness_decompose(
        &self,
        mut layouter: impl Layouter<F>,
        val: Option<F>,
    ) -> Result<[AssignedU32<F>; 8], Error> {
        layouter.assign_region(
            || "le_u32s",
            |mut region| {
                let offset = 0;
                let val = region.assign_advice(
                    || "val",
                    self.config.value,
                    offset,
                    || val.ok_or(Error::Synthesis),
                )?;
                self.assign_u32s(&mut region, offset, val)
                    .map(|u32s_and_bits| u32s_and_bits.0)
            },
        )
    }

    pub fn copy_decompose(
        &self,
        mut layouter: impl Layouter<F>,
        val: AssignedCell<F, F>,
    ) -> Result<[AssignedU32<F>; 8], Error> {
        layouter.assign_region(
            || "le_u32s",
            move |mut region| {
                let offset = 0;
                let val = val.copy_advice(|| "val", &mut region, self.config.value, offset)?;
                self.assign_u32s(&mut region, offset, val)
                    .map(|u32s_and_bits| u32s_and_bits.0)
            },
        )
    }

    pub fn witness_decompose_within_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        val: Option<F>,
    ) -> Result<[AssignedU32<F>; 8], Error> {
        let val = region.assign_advice(
            || "val",
            self.config.value,
            offset,
            || val.ok_or(Error::Synthesis),
        )?;
        self.assign_u32s(region, offset, val)
            .map(|u32s_and_bits| u32s_and_bits.0)
    }

    pub fn copy_decompose_within_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        val: AssignedCell<F, F>,
    ) -> Result<[AssignedU32<F>; 8], Error> {
        let val = val.copy_advice(|| "val", region, self.config.value, offset)?;
        self.assign_u32s(region, offset, val)
            .map(|u32s_and_bits| u32s_and_bits.0)
    }

    fn assign_u32s(
        &self,
        region: &mut Region<'_, F>,
        mut offset: usize,
        val: AssignedCell<F, F>,
    ) -> Result<([AssignedU32<F>; 8], Option<[AssignedBit<F>; 256]>), Error> {
        self.config.s_field_into_u32s.enable(region, offset)?;

        let le_bytes = val.value().map(|val| val.to_repr().as_ref().to_vec());

        // Assign `val`'s `u32` limbs in the current row.
        let u32s: [AssignedU32<F>; 8] = (0..8)
            .map(|i| {
                let limb = le_bytes.as_ref().map(|le_bytes| {
                    u32::from_le_bytes(le_bytes[i * 4..(i + 1) * 4].try_into().unwrap())
                });
                AssignedU32::assign(
                    region,
                    || format!("u32 {}", i),
                    self.config.limbs[i],
                    offset,
                    limb,
                )
            })
            .collect::<Result<Vec<AssignedU32<F>>, Error>>()
            .map(|u32s| u32s.try_into().unwrap())?;

        if self.config.s_u32_into_bits.is_none() {
            return Ok((u32s, None));
        }

        offset += 1;

        let mut bits = Vec::<AssignedBit<F>>::with_capacity(256);
        let mut bit_index = 0;

        // For each `u32` limb, allocate the limb's bits over 4 rows of 8 bits.
        for (limb_index, limb) in u32s.iter().enumerate() {
            self.config
                .s_u32_into_bits
                .unwrap()
                .enable(region, offset)?;

            limb.copy_advice(
                || format!("u32 {}", limb_index),
                region,
                self.config.value,
                offset,
            )?;

            let bytes = limb.value_u32().map(|limb| limb.to_le_bytes());

            for byte_index in 0..4 {
                let byte = bytes.as_ref().map(|bytes| bytes[byte_index]);
                for i in 0..8 {
                    let bit = region.assign_advice(
                        || format!("u32 {} bit {}", limb_index, bit_index),
                        self.config.limbs[i],
                        offset,
                        || {
                            byte.map(|byte| Bit(byte >> i & 1 == 1))
                                .ok_or(Error::Synthesis)
                        },
                    )?;
                    bits.push(bit);
                    bit_index += 1;
                }
                offset += 1;
            }
        }

        Ok((u32s, Some(bits.try_into().unwrap())))
    }

    // # Panics
    //
    // Panics if `limbs` do not represent a valid field element.
    pub fn pack(
        &self,
        mut layouter: impl Layouter<F>,
        limbs: &[AssignedU32<F>; 8],
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "pack_u32s",
            |mut region| {
                let offset = 0;

                self.config.s_field_into_u32s.enable(&mut region, offset)?;

                let limbs = limbs
                    .iter()
                    .zip(self.config.limbs.iter())
                    .enumerate()
                    .map(|(i, (limb, col))| {
                        limb.copy_advice(|| format!("copy limb {}", i), &mut region, *col, offset)
                            .map(AssignedBits)
                    })
                    .collect::<Result<Vec<AssignedU32<F>>, Error>>()?;

                let mut repr = Some(F::Repr::default());
                for (i, limb) in limbs.iter().enumerate() {
                    let limb_bytes = limb.value_u32().map(|limb| limb.to_le_bytes());
                    repr = repr.zip(limb_bytes).map(|(mut repr, limb_bytes)| {
                        repr.as_mut()[i * 4..(i + 1) * 4].copy_from_slice(&limb_bytes);
                        repr
                    });
                }
                let packed =
                    repr.map(|repr| F::from_repr_vartime(repr).expect("limbs are invalid repr"));

                region.assign_advice(
                    || "val",
                    self.config.value,
                    offset,
                    || packed.ok_or(Error::Synthesis),
                )
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct UInt32Config<F: FieldExt> {
    value: Column<Advice>,
    bits: [Column<Advice>; 8],
    s_field_into_32_bits: Selector,
    _f: PhantomData<F>,
}

impl<F: FieldExt> UInt32Config<F> {
    pub fn value_col(&self) -> Column<Advice> {
        self.value
    }
}

#[derive(Clone, Debug)]
pub struct UInt32Chip<F: FieldExt> {
    config: UInt32Config<F>,
}

impl<F: FieldExt> UInt32Chip<F> {
    pub fn construct(config: UInt32Config<F>) -> Self {
        UInt32Chip { config }
    }

    pub fn num_cols() -> NumCols {
        U32_DECOMP_NUM_COLS
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 9],
    ) -> UInt32Config<F> {
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let value = advice[0];
        let bits: [Column<Advice>; 8] = advice[1..].try_into().unwrap();

        let mut radix_pows = Vec::with_capacity(31);
        radix_pows.push(F::from(2));
        for i in 0..30 {
            radix_pows.push(radix_pows[i].double());
        }

        let s_field_into_32_bits = meta.selector();
        meta.create_gate("field into 32 bits", |meta| {
            let s = meta.query_selector(s_field_into_32_bits);
            let value = meta.query_advice(value, Rotation::cur());

            let mut radix_pows = radix_pows.into_iter().map(Expression::Constant);

            let mut expr = meta.query_advice(bits[0], Rotation::cur());
            for col in &bits[1..] {
                let bit = meta.query_advice(*col, Rotation::cur());
                expr = expr + radix_pows.next().unwrap() * bit;
            }
            for offset in 1..4 {
                let offset = Rotation(offset as i32);
                for col in &bits {
                    let bit = meta.query_advice(*col, offset);
                    expr = expr + radix_pows.next().unwrap() * bit;
                }
            }

            [s * (expr - value)]
        });

        UInt32Config {
            value,
            bits,
            s_field_into_32_bits,
            _f: PhantomData,
        }
    }

    pub fn assign_bits(
        &self,
        region: &mut Region<'_, F>,
        mut offset: usize,
        value: AssignedU32<F>,
    ) -> Result<[AssignedBit<F>; 32], Error> {
        self.config.s_field_into_32_bits.enable(region, offset)?;

        let val = value.value_u32();

        let mut bits = Vec::with_capacity(32);
        let mut bit_index = 0;

        for _ in 0..4 {
            for col in self.config.bits.iter() {
                let bit = region.assign_advice(
                    || format!("bit {}", bit_index),
                    *col,
                    offset,
                    || {
                        val.map(|val| Bit(val >> bit_index & 1 == 1))
                            .ok_or(Error::Synthesis)
                    },
                )?;
                bits.push(bit);
                bit_index += 1;
            }
            offset += 1;
        }

        Ok(bits.try_into().unwrap())
    }

    pub fn pi_assign_bits(
        &self,
        mut layouter: impl Layouter<F>,
        pi_col: Column<Instance>,
        pi_row: usize,
    ) -> Result<[AssignedBit<F>; 32], Error> {
        layouter.assign_region(
            || "assign public input as 32 bits",
            |mut region| {
                let offset = 0;
                self.config.s_field_into_32_bits.enable(&mut region, offset)?;

                // Copy challenge public input.
                let pi = region.assign_advice_from_instance(
                    || "copy public input",
                    pi_col,
                    pi_row,
                    self.config.value,
                    offset,
                )?;

                let pi_bytes: Option<[u8; 4]> =
                    pi.value().map(|pi| pi.to_repr().as_ref()[..4].try_into().unwrap());

                let mut pi_bits = Vec::with_capacity(32);
                let mut bit_index = 0;

                for byte_index in 0..4 {
                    let byte = pi_bytes.map(|bytes| bytes[byte_index]);
                    for i in 0..8 {
                        let bit = region.assign_advice(
                            || format!("bit {}", bit_index),
                            self.config.bits[i],
                            byte_index,
                            || byte.map(|byte| Bit(byte >> i & 1 == 1)).ok_or(Error::Synthesis),
                        )?;
                        pi_bits.push(bit);
                        bit_index += 1;
                    }
                }

                Ok(pi_bits.try_into().unwrap())
            },
        )
    }
}

#[derive(Clone, Debug)]
pub struct StripBitsConfig<F: FieldExt> {
    value: Column<Advice>,
    bits: [Column<Advice>; 8],
    s_strip_bits: Selector,
    _f: PhantomData<F>,
}

pub struct StripBitsChip<F: FieldExt> {
    config: StripBitsConfig<F>,
}

impl<F: FieldExt> StripBitsChip<F> {
    pub fn construct(config: StripBitsConfig<F>) -> Self {
        StripBitsChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 9],
    ) -> StripBitsConfig<F> {
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        let value = advice[0];
        let bits: [Column<Advice>; 8] = advice[1..].try_into().unwrap();

        let s_strip_bits = meta.selector();

        let mut radix_pows = Vec::with_capacity(31);
        let radix = F::from(2);
        radix_pows.push(radix);
        for i in 0..30 {
            radix_pows.push(radix_pows[i] * radix);
        }

        meta.create_gate("u32_strip_bits", |meta| {
            let s_strip_bits = meta.query_selector(s_strip_bits);

            let value_u32 = meta.query_advice(value, Rotation::cur());
            let value_u30 = meta.query_advice(value, Rotation::next());

            let mut radix_pows = radix_pows.into_iter().map(Expression::Constant);

            // Linear combination of first 30 bits.
            let mut expr_u30 = meta.query_advice(bits[0], Rotation::cur());
            for col in bits[1..].iter() {
                let bit = meta.query_advice(*col, Rotation::cur());
                expr_u30 = expr_u30 + radix_pows.next().unwrap() * bit;
            }
            for row in 1..3 {
                for col in bits.iter() {
                    let bit = meta.query_advice(*col, Rotation(row as i32));
                    expr_u30 = expr_u30 + radix_pows.next().unwrap() * bit;
                }
            }
            let row = 3;
            for col in bits[..6].iter() {
                let bit = meta.query_advice(*col, Rotation(row as i32));
                expr_u30 = expr_u30 + radix_pows.next().unwrap() * bit;
            }

            // Linear combination of all bits.
            let mut expr_u32 = expr_u30.clone();
            for col in bits[6..].iter() {
                let bit = meta.query_advice(*col, Rotation(row as i32));
                expr_u32 = expr_u32 + radix_pows.next().unwrap() * bit;
            }

            Constraints::with_selector(
                s_strip_bits,
                [
                    ("32-bit packing", expr_u32 - value_u32),
                    ("30-bit packing", expr_u30 - value_u30),
                ],
            )
        });

        StripBitsConfig {
            value,
            bits,
            s_strip_bits,
            _f: PhantomData,
        }
    }

    // | ----- | ------ | ------ | --- | ------ | ------------- |
    // |  a_1  |  a_2   |  a_3   | ... |  a_9   | s_strip_bits  |
    // | ----- | ------ | ------ | --- | ------ | ------------- |
    // |  u32  | bit_1  | bit_2  | ... | bit_8  |         1     |
    // |  u30  | bit_9  | bit_10 | ... | bit_16 |         0     |
    // |       | bit_17 | bit_18 | ... | bit_24 |         0     |
    // |       | bit_25 | bit_26 | ... | bit_32 |         0     |
    pub fn strip_bits(
        &self,
        mut layouter: impl Layouter<F>,
        value_u32: &AssignedU32<F>,
    ) -> Result<AssignedU32<F>, Error> {
        layouter.assign_region(
            || "u32_strip_bits",
            |mut region| {
                let mut offset = 0;

                self.config.s_strip_bits.enable(&mut region, offset)?;

                let value_u32 = value_u32
                    .copy_advice(|| "copy value_u32", &mut region, self.config.value, offset)
                    .map(AssignedBits)?;

                let value_u32 = value_u32.value_u32();
                let mut bits_iter = (0..32).map(|i| value_u32.map(|val| val >> i & 1 == 1));
                let mut bits = Vec::with_capacity(32);
                let mut bit_index = 0;

                for offset in 0..4 {
                    for col in self.config.bits.iter() {
                        let bit = region.assign_advice(
                            || format!("bit {}", bit_index),
                            *col,
                            offset,
                            || bits_iter.next().unwrap().map(Bit).ok_or(Error::Synthesis),
                        )?;
                        bits.push(bit);
                        bit_index += 1;
                    }
                }

                offset += 1;

                // `mask = 0b00111111_11111111_11111111_11111111`
                let mask = (1 << 30) - 1;
                AssignedU32::assign(
                    &mut region,
                    || "value_u30",
                    self.config.value,
                    offset,
                    value_u32.map(|val| val & mask),
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::TEST_SEED;

    struct MyCircuit<F: FieldExt> {
        value: Option<F>,
    }

    impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
        type Config = (U32DecompConfig<F>, StripBitsConfig<F>);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit { value: None }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let advice = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            let decomp = U32DecompChip::configure(meta, advice);
            let strip_bits = StripBitsChip::configure(meta, advice);
            (decomp, strip_bits)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let (decomp_config, strip_bits_config) = config;

            let decomp_chip = U32DecompChip::construct(decomp_config);
            let strip_bits_chip = StripBitsChip::construct(strip_bits_config);

            let u32s =
                decomp_chip.witness_decompose(layouter.namespace(|| "decomp"), self.value)?;
            let packed = decomp_chip.pack(layouter.namespace(|| "pack"), &u32s)?;
            let stripped =
                strip_bits_chip.strip_bits(layouter.namespace(|| "strip bits"), &u32s[0])?;

            let expected_u32s: Vec<u32> = self
                .value
                .unwrap()
                .to_repr()
                .as_ref()
                .chunks(4)
                .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                .collect();
            let expected_packed = self.value.unwrap();
            let expected_stripped = {
                let mut repr: [u8; 4] = expected_packed.to_repr().as_ref()[..4].try_into().unwrap();
                repr[3] &= 0b0011_1111;
                u32::from_le_bytes(repr)
            };

            assert_eq!(
                u32s.iter()
                    .map(|limb| limb.value_u32().unwrap())
                    .collect::<Vec<u32>>(),
                expected_u32s,
            );
            assert_eq!(packed.value().unwrap(), &expected_packed);
            assert_eq!(stripped.value_u32().unwrap(), expected_stripped);

            Ok(())
        }
    }

    #[test]
    fn test_u32_chips() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        // Test using a random field element.
        let circ = MyCircuit {
            value: Some(Fp::random(&mut rng)),
        };
        let prover = MockProver::run(4, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());

        // Test using the largest field element `p - 1`.
        let circ = MyCircuit {
            value: Some(Fp::zero() - Fp::one()),
        };
        let prover = MockProver::run(4, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
