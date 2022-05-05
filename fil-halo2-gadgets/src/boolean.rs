use std::convert::TryInto;

pub use halo2_gadgets::utilities::bool_check;

use ff::PrimeFieldBits;
use halo2_gadgets::utilities::decompose_running_sum::{RunningSum, RunningSumConfig};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Region},
    plonk::{Advice, Any, Assigned, Column, ConstraintSystem, Error, Expression},
    poly::Rotation,
};

// Equal to `F::NUM_BITS`.
const FIELD_BITS: usize = 255;

// Decompose each field element into 3-bit windows.
const WINDOW_BITS: usize = 3;
const NUM_WINDOWS: usize = FIELD_BITS / WINDOW_BITS;

// Returns `1` if both `b0` and `b1` are `1`.
//
// Assumes `bit_0` and `bit_1` are already boolean constrained.
#[inline]
pub fn and<F: FieldExt>(bit_0: Expression<F>, bit_1: Expression<F>) -> Expression<F> {
    bit_0 * bit_1
}

// Returns `1` if both `b0` and `b1` are `0`.
//
// Assumes `bit_0` and `bit_1` are already boolean constrained.
#[inline]
pub fn nor<F: FieldExt>(bit_0: Expression<F>, bit_1: Expression<F>) -> Expression<F> {
    (Expression::Constant(F::one()) - bit_0) * (Expression::Constant(F::one()) - bit_1)
}

pub fn lebs2ip<const K: usize>(bits: &[bool; K]) -> u64 {
    assert!(K <= 64);
    bits.iter()
        .enumerate()
        .fold(0u64, |acc, (i, b)| acc + if *b { 1 << i } else { 0 })
}

pub fn i2lebsp<const NUM_BITS: usize>(int: u64) -> [bool; NUM_BITS] {
    /// Takes in an FnMut closure and returns a constant-length array with elements of
    /// type `Output`.
    fn gen_const_array<Output: Copy + Default, const LEN: usize>(
        closure: impl FnMut(usize) -> Output,
    ) -> [Output; LEN] {
        gen_const_array_with_default(Default::default(), closure)
    }

    fn gen_const_array_with_default<Output: Copy, const LEN: usize>(
        default_value: Output,
        mut closure: impl FnMut(usize) -> Output,
    ) -> [Output; LEN] {
        let mut ret: [Output; LEN] = [default_value; LEN];
        for (bit, val) in ret.iter_mut().zip((0..LEN).map(|idx| closure(idx))) {
            *bit = val;
        }
        ret
    }

    assert!(NUM_BITS <= 64);
    gen_const_array(|mask: usize| (int & (1 << mask)) != 0)
}

/// Helper function that interleaves a little-endian bit-array with zeros
/// in the odd indices. That is, it takes the array
///         [b_0, b_1, ..., b_n]
/// to
///         [b_0, 0, b_1, 0, ..., b_n, 0].
/// Panics if bit-array is longer than 16 bits.
pub fn spread_bits<const DENSE: usize, const SPREAD: usize>(
    bits: impl Into<[bool; DENSE]>,
) -> [bool; SPREAD] {
    assert_eq!(DENSE * 2, SPREAD);
    assert!(DENSE <= 16);

    let bits: [bool; DENSE] = bits.into();
    let mut spread = [false; SPREAD];

    for (idx, bit) in bits.iter().enumerate() {
        spread[idx * 2] = *bit;
    }

    spread
}

pub type AssignedBit<F> = AssignedCell<Bit, F>;

#[derive(Clone, Debug)]
pub struct Bit(pub bool);

impl<F: FieldExt> From<&Bit> for Assigned<F> {
    fn from(bit: &Bit) -> Self {
        if bit.0 {
            F::one().into()
        } else {
            F::zero().into()
        }
    }
}

impl From<bool> for Bit {
    fn from(bit: bool) -> Self {
        Bit(bit)
    }
}

impl From<Bit> for bool {
    fn from(bit: Bit) -> Self {
        bit.0
    }
}

impl From<&Bit> for bool {
    fn from(bit: &Bit) -> Self {
        bit.0
    }
}

/// Little-endian bits (up to 64 bits)
#[derive(Clone, Debug)]
pub struct Bits<const LEN: usize>(pub(crate) [bool; LEN]);

impl<const LEN: usize> Bits<LEN> {
    pub(crate) fn spread<const SPREAD: usize>(&self) -> [bool; SPREAD] {
        spread_bits(self.0)
    }
}

impl<const LEN: usize> std::ops::Deref for Bits<LEN> {
    type Target = [bool; LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LEN: usize> From<[bool; LEN]> for Bits<LEN> {
    fn from(bits: [bool; LEN]) -> Self {
        Self(bits)
    }
}

impl<const LEN: usize> From<&Bits<LEN>> for [bool; LEN] {
    fn from(bits: &Bits<LEN>) -> Self {
        bits.0
    }
}

impl<F: FieldExt, const LEN: usize> From<&Bits<LEN>> for Assigned<F> {
    fn from(bits: &Bits<LEN>) -> Assigned<F> {
        assert!(LEN <= 64);
        F::from(lebs2ip(&bits.0)).into()
    }
}

impl From<&Bits<16>> for u16 {
    fn from(bits: &Bits<16>) -> u16 {
        lebs2ip(&bits.0) as u16
    }
}

impl From<u16> for Bits<16> {
    fn from(int: u16) -> Bits<16> {
        Bits(i2lebsp::<16>(int.into()))
    }
}

impl From<&Bits<32>> for u32 {
    fn from(bits: &Bits<32>) -> u32 {
        lebs2ip(&bits.0) as u32
    }
}

impl From<u32> for Bits<32> {
    fn from(int: u32) -> Bits<32> {
        Bits(i2lebsp::<32>(int.into()))
    }
}

#[derive(Clone, Debug)]
pub struct AssignedBits<F: FieldExt, const LEN: usize>(pub(crate) AssignedCell<Bits<LEN>, F>);

impl<F: FieldExt, const LEN: usize> std::ops::Deref for AssignedBits<F, LEN> {
    type Target = AssignedCell<Bits<LEN>, F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: FieldExt, const LEN: usize> AssignedBits<F, LEN> {
    pub fn assign_bits<A, AR, T: TryInto<[bool; LEN]> + std::fmt::Debug + Clone>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Option<T>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
        <T as TryInto<[bool; LEN]>>::Error: std::fmt::Debug,
    {
        let value: Option<[bool; LEN]> = value.map(|v| v.try_into().unwrap());
        let value: Option<Bits<LEN>> = value.map(|v| v.into());

        let column: Column<Any> = column.into();
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone().ok_or(Error::Synthesis)
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone().ok_or(Error::Synthesis)
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl<F: FieldExt> AssignedBits<F, 16> {
    pub fn value_u16(&self) -> Option<u16> {
        self.value().map(|v| v.into())
    }

    pub fn assign<A, AR>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Option<u16>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Option<Bits<16>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone().ok_or(Error::Synthesis)
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone().ok_or(Error::Synthesis)
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

impl<F: FieldExt> AssignedBits<F, 32> {
    pub fn value_u32(&self) -> Option<u32> {
        self.value().map(|v| v.into())
    }

    pub fn assign<A, AR>(
        region: &mut Region<'_, F>,
        annotation: A,
        column: impl Into<Column<Any>>,
        offset: usize,
        value: Option<u32>,
    ) -> Result<Self, Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        let column: Column<Any> = column.into();
        let value: Option<Bits<32>> = value.map(|v| v.into());
        match column.column_type() {
            Any::Advice => {
                region.assign_advice(annotation, column.try_into().unwrap(), offset, || {
                    value.clone().ok_or(Error::Synthesis)
                })
            }
            Any::Fixed => {
                region.assign_fixed(annotation, column.try_into().unwrap(), offset, || {
                    value.clone().ok_or(Error::Synthesis)
                })
            }
            _ => panic!("Cannot assign to instance column"),
        }
        .map(AssignedBits)
    }
}

#[derive(Clone, Debug)]
pub struct LeBitsConfig<F>
where
    F: FieldExt + PrimeFieldBits,
{
    // One column to store a field element to be decomposed (as well as each of the element's
    // running sum windows `z_i`) and one column for each of the window's 3 bits.
    advice: [Column<Advice>; 1 + WINDOW_BITS],
    running_sum: RunningSumConfig<F, WINDOW_BITS>,
}

pub struct LeBitsChip<F>
where
    F: FieldExt + PrimeFieldBits,
{
    config: LeBitsConfig<F>,
}

impl<F> LeBitsChip<F>
where
    F: FieldExt + PrimeFieldBits,
{
    pub fn construct(config: LeBitsConfig<F>) -> Self {
        LeBitsChip { config }
    }

    // # Side Effects
    //
    // `advice[0]` will be equality constrained.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 1 + WINDOW_BITS],
    ) -> LeBitsConfig<F> {
        // Running sum chip requires one fixed column.
        let fixed = meta.fixed_column();
        meta.enable_constant(fixed);
        let s_running_sum = meta.selector();
        let running_sum = RunningSumConfig::configure(meta, s_running_sum, advice[0]);

        let two = F::from(2);
        let four = F::from(4);
        let radix = F::from(1 << WINDOW_BITS);

        meta.create_gate("pack window bits", |meta| {
            // Reuse the running sum's selector.
            let s_running_sum = meta.query_selector(s_running_sum);

            let z_cur = meta.query_advice(advice[0], Rotation::cur());
            let z_next = meta.query_advice(advice[0], Rotation::next());
            let bit_1 = meta.query_advice(advice[1], Rotation::cur());
            let bit_2 = meta.query_advice(advice[2], Rotation::cur());
            let bit_3 = meta.query_advice(advice[3], Rotation::cur());

            let bool_check_1 = bool_check(bit_1.clone());
            let bool_check_2 = bool_check(bit_2.clone());
            let bool_check_3 = bool_check(bit_3.clone());

            let k_cur = z_cur - Expression::Constant(radix) * z_next;
            let k_cur_from_bits =
                bit_1 + bit_2 * Expression::Constant(two) + bit_3 * Expression::Constant(four);

            vec![
                s_running_sum.clone() * bool_check_1,
                s_running_sum.clone() * bool_check_2,
                s_running_sum.clone() * bool_check_3,
                s_running_sum * (k_cur_from_bits - k_cur),
            ]
        });

        LeBitsConfig {
            advice,
            running_sum,
        }
    }

    pub fn witness_decompose(
        &self,
        mut layouter: impl Layouter<F>,
        val: Option<F>,
    ) -> Result<Vec<AssignedBit<F>>, Error> {
        layouter.assign_region(
            || "le_bits",
            |mut region| {
                let offset = 0;
                self.witness_decompose_within_region(&mut region, offset, val)
            },
        )
    }

    pub fn copy_decompose(
        &self,
        mut layouter: impl Layouter<F>,
        val: AssignedCell<F, F>,
    ) -> Result<Vec<AssignedBit<F>>, Error> {
        layouter.assign_region(
            || "le_bits",
            move |mut region| {
                let offset = 0;
                self.copy_decompose_within_region(&mut region, offset, val.clone())
            },
        )
    }

    pub fn witness_decompose_within_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        val: Option<F>,
    ) -> Result<Vec<AssignedBit<F>>, Error> {
        let zs = self.config.running_sum.witness_decompose(
            region,
            offset,
            val,
            true,
            FIELD_BITS,
            NUM_WINDOWS,
        )?;
        self.assign_bits(region, offset, zs)
    }

    pub fn copy_decompose_within_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        val: AssignedCell<F, F>,
    ) -> Result<Vec<AssignedBit<F>>, Error> {
        let zs = self.config.running_sum.copy_decompose(
            region,
            offset,
            val,
            true,
            FIELD_BITS,
            NUM_WINDOWS,
        )?;
        self.assign_bits(region, offset, zs)
    }

    fn assign_bits(
        &self,
        region: &mut Region<'_, F>,
        mut offset: usize,
        zs: RunningSum<F>,
    ) -> Result<Vec<AssignedBit<F>>, Error> {
        let mut bits = Vec::with_capacity(FIELD_BITS);
        let mut bit_index = 0;
        let radix = F::from(1 << WINDOW_BITS);

        for z_index in 0..NUM_WINDOWS {
            let z_cur = zs[z_index].value();
            let z_next = zs[z_index + 1].value();

            let k_cur = z_cur.zip(z_next).map(|(z_cur, z_next)| {
                let k_cur = *z_cur - radix * z_next;
                // The running sum guarantees that each `k_i` is in `0..2^3`.
                k_cur.to_repr().as_ref()[0]
            });

            for i in 0..WINDOW_BITS {
                let bit = region.assign_advice(
                    || format!("bit {}", bit_index),
                    // The first advice column stores `z_i`, the remaining advice columns
                    // store `k_i`'s bits.
                    self.config.advice[1 + i],
                    offset,
                    || {
                        k_cur
                            .map(|k_cur| Bit(k_cur >> i & 1 == 1))
                            .ok_or(Error::Synthesis)
                    },
                )?;
                bits.push(bit);
                bit_index += 1;
            }

            offset += 1;
        }

        Ok(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryInto;

    use ff::Field;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::TEST_SEED;

    struct MyCircuit<F>
    where
        F: FieldExt + PrimeFieldBits,
    {
        value: Option<F>,
    }

    impl<F> Circuit<F> for MyCircuit<F>
    where
        F: FieldExt + PrimeFieldBits,
    {
        type Config = LeBitsConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit { value: None }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let advice: [Column<Advice>; 1 + WINDOW_BITS] = (0..1 + WINDOW_BITS)
                .map(|_| meta.advice_column())
                .collect::<Vec<Column<Advice>>>()
                .try_into()
                .unwrap();

            LeBitsChip::configure(meta, advice)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // Assign `self.value` in the first advice column because that column is equality
            // constrained by the running sum chip.
            let value_col = config.advice[0];

            let le_bits_chip = LeBitsChip::construct(config);

            let bits: Vec<Option<bool>> = layouter
                .assign_region(
                    || "decompose",
                    |mut region| {
                        let mut offset = 0;
                        let value = region.assign_advice(
                            || "value",
                            value_col,
                            offset,
                            || self.value.ok_or(Error::Synthesis),
                        )?;
                        offset += 1;
                        le_bits_chip.copy_decompose_within_region(&mut region, offset, value)
                    },
                )?
                .into_iter()
                .map(|asn| asn.value().map(Into::into))
                .collect();

            let expected_bits = if bits.iter().any(Option::is_none) {
                assert!(self.value.is_none());
                vec![None; FIELD_BITS]
            } else {
                assert!(self.value.is_some());
                self.value
                    .unwrap()
                    .to_le_bits()
                    .into_iter()
                    .map(Some)
                    .take(FIELD_BITS)
                    .collect()
            };

            assert_eq!(bits, expected_bits);

            Ok(())
        }
    }

    impl<F> MyCircuit<F>
    where
        F: FieldExt + PrimeFieldBits,
    {
        fn k() -> u32 {
            // `k = ceil(log2(NUM_WINDOWS + 1))`; the number of running sum rows is `NUM_WINDOWS`;
            // add one row for the initial assignment of `self.value`.
            7
        }
    }

    #[test]
    fn test_le_bits_chip() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);
        let value = Some(Fp::random(&mut rng));
        let circ = MyCircuit { value };
        let k = MyCircuit::<Fp>::k();
        let prover = MockProver::run(k, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
