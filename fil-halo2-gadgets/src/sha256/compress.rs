#![allow(clippy::large_enum_variant)]
#![allow(clippy::unusual_byte_groupings)]

use std::convert::TryInto;
use std::iter;
use std::marker::PhantomData;
use std::ops::Range;

use halo2_gadgets::utilities::bool_check;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{
        Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Fixed,
        Instance, Selector, VirtualCells,
    },
    poly::Rotation,
};
use sha2::{Digest, Sha256};

pub use crate::sha256::{
    table16::{IV, STATE as STATE_WORDS},
    BLOCK_SIZE as BLOCK_WORDS, FIELD_WORD_LEN as FIELD_WORDS, PAD_WORDS,
};

use crate::{
    boolean::{pack_bits, AssignedBit, Bit},
    convert_assigned_f,
    sha256::{
        get_padding,
        table16::{ROUNDS as NUM_ROUNDS, ROUND_CONSTANTS},
    },
    AdviceIter, ColumnCount, NumCols,
};

// The maximum number of words that can be utilized in the last block of a sha256 preimage.
pub const BLOCK_WORDS_UNPADDED: usize = BLOCK_WORDS - PAD_WORDS;

// Each `u32` word is 4 bytes.
pub const WORD_BYTES: usize = 4;

// Number of public inputs per input state word; 32 bits and 1 packed `u32`.
pub const WORD_PUB_INPUTS: usize = 33;

// Number of public inputs for all input state words.
pub const STATE_PUB_INPUTS: usize = STATE_WORDS * WORD_PUB_INPUTS;

// Maximum number of inputs to `CompressChip::modular_sum()`.
const MODULAR_SUM_OPERANDS: usize = 5;

// AND-mask that zeros the two most significant bits of a `u32`.
pub(crate) const STRIP_MASK: u32 = 0b00111111_11111111_11111111_11111111;

#[cfg(feature = "all-chips")]
pub(crate) fn f_to_u32s<F: FieldExt>(f: &F) -> [u32; FIELD_WORDS] {
    f.to_repr()
        .as_ref()
        .chunks(WORD_BYTES)
        .map(|word_bytes| u32::from_le_bytes(word_bytes.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap()
}

pub(crate) fn f_to_words<F: FieldExt>(f: &F) -> [u32; FIELD_WORDS] {
    f.to_repr()
        .as_ref()
        .chunks(WORD_BYTES)
        .map(|word_bytes| u32::from_be_bytes(word_bytes.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap()
}

#[allow(dead_code)]
fn u32s_to_f<F: FieldExt>(u32s: &[u32; FIELD_WORDS]) -> F {
    let repr_bytes: Vec<u8> = u32s.iter().fold(Vec::with_capacity(32), |mut bytes, u32_| {
        bytes.extend(u32_.to_le_bytes());
        bytes
    });
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(&repr_bytes);
    F::from_repr_vartime(repr).expect("u32s are invalid field element")
}

// Common `Value` operations.
pub mod values {
    use super::*;

    pub(crate) fn words_to_u32s(words: &[Value<u32>; STATE_WORDS]) -> [Value<u32>; STATE_WORDS] {
        words
            .iter()
            .map(|word| word.map(u32::swap_bytes))
            .collect::<Vec<Value<u32>>>()
            .try_into()
            .unwrap()
    }

    #[cfg(feature = "all-chips")]
    pub(crate) fn f_to_u32s<F: FieldExt>(f: &Value<F>) -> [Value<u32>; FIELD_WORDS] {
        f.as_ref().map(super::f_to_u32s).transpose_array()
    }

    pub(crate) fn f_to_words<F: FieldExt>(f: &Value<F>) -> [Value<u32>; FIELD_WORDS] {
        f.as_ref().map(super::f_to_words).transpose_array()
    }

    pub(crate) fn u32s_to_f<F: FieldExt>(u32s: &[Value<u32>; FIELD_WORDS]) -> Value<F> {
        u32s.iter()
            .copied()
            .fold(Value::known(Vec::<u8>::with_capacity(32)), |bytes, u32_| {
                bytes.zip(u32_).map(|(mut bytes, u32_)| {
                    bytes.extend(u32_.to_le_bytes());
                    bytes
                })
            })
            .map(|bytes| {
                let mut repr = F::Repr::default();
                repr.as_mut().copy_from_slice(&bytes);
                F::from_repr_vartime(repr).expect("u32s are invalid field element")
            })
    }

    #[allow(dead_code)]
    pub(crate) fn words_to_f<F: FieldExt>(words: &[Value<u32>; FIELD_WORDS]) -> Value<F> {
        u32s_to_f(&words_to_u32s(words))
    }

    pub(crate) fn strip_bits(word: &mut Value<u32>) {
        word.as_mut().map(|word| *word &= STRIP_MASK);
    }

    pub fn hash_words_padded(preimage: &[Value<u32>]) -> [Value<u32>; STATE_WORDS] {
        assert!(!preimage.is_empty(), "cannot hash empty preimage");
        let padded_word_len = preimage.len();

        let mut padded_preimage_words = Vec::<u32>::with_capacity(padded_word_len);
        for word in preimage.iter() {
            word.map(|word| padded_preimage_words.push(word));
        }
        assert_eq!(
            padded_preimage_words.len(),
            padded_word_len,
            "cannot hash `Value::unknown`s",
        );

        let unpadded_word_len = {
            let lo = padded_preimage_words[padded_word_len - 1] as usize;
            let hi = padded_preimage_words[padded_word_len - 2] as usize;
            let unpadded_bit_len = lo + (hi << 32);
            assert_eq!(unpadded_bit_len % 32, 0);
            unpadded_bit_len / 32
        };

        let unpadded_preimage_bytes: Vec<u8> = padded_preimage_words
            .iter()
            .take(unpadded_word_len)
            .flat_map(|word| word.to_be_bytes())
            .collect();

        let digest_bytes = Sha256::digest(&unpadded_preimage_bytes);

        digest_bytes
            .chunks(WORD_BYTES)
            .map(|word_bytes| {
                let word_bytes: [u8; 4] = word_bytes.try_into().unwrap();
                Value::known(u32::from_be_bytes(word_bytes))
            })
            .collect::<Vec<Value<u32>>>()
            .try_into()
            .unwrap()
    }

    pub fn hash_blocks_padded(blocks: &[[Value<u32>; BLOCK_WORDS]]) -> [Value<u32>; STATE_WORDS] {
        let preimage_words: Vec<Value<u32>> = blocks.iter().cloned().flatten().collect();
        hash_words_padded(&preimage_words)
    }

    pub fn hash_field_elems_padded<F: FieldExt>(preimage: &[Value<F>]) -> Value<F> {
        let preimage_words: Vec<Value<u32>> = preimage.iter().flat_map(f_to_words).collect();
        let digest_words = hash_words_padded(&preimage_words);
        let mut digest_u32s = words_to_u32s(&digest_words);
        strip_bits(digest_u32s.last_mut().unwrap());
        values::u32s_to_f(&digest_u32s)
    }

    pub fn hash_field_elems_unpadded<F: FieldExt>(preimage: &[Value<F>]) -> Value<F> {
        let unpadded_preimage_word_len = preimage.len() * FIELD_WORDS;
        let unpadded_preimage_words = preimage.iter().flat_map(f_to_words);
        let padding = get_padding(unpadded_preimage_word_len)
            .into_iter()
            .map(Value::known);
        let padded_preimage_words: Vec<Value<u32>> =
            unpadded_preimage_words.chain(padding).collect();

        let digest_words = hash_words_padded(&padded_preimage_words);
        let mut digest_u32s = words_to_u32s(&digest_words);
        strip_bits(digest_u32s.last_mut().unwrap());
        values::u32s_to_f(&digest_u32s)
    }
}

// Unassigned `u32`.
#[derive(Debug, Clone, Copy)]
pub struct U32(pub(crate) u32);

impl From<U32> for u32 {
    fn from(uint: U32) -> Self {
        uint.0
    }
}

impl From<&U32> for u32 {
    fn from(uint: &U32) -> Self {
        uint.0
    }
}

impl From<&U32> for u64 {
    fn from(uint: &U32) -> Self {
        uint.0 as u64
    }
}

impl<F: FieldExt> From<&F> for U32 {
    fn from(f: &F) -> Self {
        let repr = f.to_repr();
        assert!(repr.as_ref().iter().skip(4).all(|byte| *byte == 0));
        let word_bytes: [u8; 4] = repr.as_ref()[..4].try_into().unwrap();
        U32(u32::from_le_bytes(word_bytes))
    }
}

impl<F: FieldExt> From<&U32> for Assigned<F> {
    fn from(uint32: &U32) -> Assigned<F> {
        F::from(uint32.0 as u64).into()
    }
}

// Assigned `u32`.
pub type AssignedU32<F> = AssignedCell<U32, F>;

#[derive(Debug, Clone)]
pub struct Word<F: FieldExt> {
    // Least-significant bit first. Right-shifting a word by `n` will cause its `n` most significant
    // bits to be `None`.
    pub(crate) bits: [Option<AssignedBit<F>>; 32],
    // Not all assigned words will need to be packed into an `u32`.
    pub(crate) int: Option<AssignedU32<F>>,
    // The offset of the first row of this word in the sha256 compression region.
    pub(crate) offset: usize,
}

impl<F: FieldExt> Word<F> {
    pub(crate) fn bits_unchecked(&self) -> [&AssignedBit<F>; 32] {
        self.bits
            .iter()
            .map(|bit| bit.as_ref().unwrap())
            .collect::<Vec<&AssignedBit<F>>>()
            .try_into()
            .unwrap()
    }

    pub(crate) fn int_unchecked(&self) -> &AssignedU32<F> {
        self.int.as_ref().unwrap()
    }

    fn rotr(&self, n: usize) -> Self {
        let n = n % 32;
        // All `self.bits` should be `Some`.
        let bits = self
            .bits
            .iter()
            .skip(n)
            .chain(&self.bits)
            .take(32)
            .cloned()
            .collect::<Vec<Option<AssignedBit<F>>>>()
            .try_into()
            .unwrap();
        Word {
            bits,
            int: None,
            offset: self.offset,
        }
    }

    fn shr(&self, n: usize) -> Self {
        let n = n % 32;
        let bits = self
            .bits
            .iter()
            .skip(n)
            .cloned()
            .chain(iter::repeat(None))
            .take(32)
            .collect::<Vec<Option<AssignedBit<F>>>>()
            .try_into()
            .unwrap();
        Word {
            bits,
            int: None,
            offset: self.offset,
        }
    }

    pub fn value_u32(&self) -> Value<u32> {
        match self.int {
            Some(ref int) => int.value().map(u32::from),
            None => self
                .bits
                .iter()
                .filter(|bit| bit.is_some())
                .enumerate()
                .fold(Value::known(0), |acc, (i, bit)| {
                    acc + bit
                        .as_ref()
                        .unwrap()
                        .value()
                        .map(|bit| (bool::from(bit) as u32) << i)
                }),
        }
    }
}

#[derive(Debug)]
pub enum InputBlock<F: FieldExt> {
    Unassigned([Value<u32>; BLOCK_WORDS]),
    Assigned([Word<F>; BLOCK_WORDS]),
}

impl<F: FieldExt> From<[Value<u32>; BLOCK_WORDS]> for InputBlock<F> {
    fn from(block: [Value<u32>; BLOCK_WORDS]) -> Self {
        InputBlock::Unassigned(block)
    }
}

impl<F: FieldExt> From<&[Value<u32>; BLOCK_WORDS]> for InputBlock<F> {
    fn from(block: &[Value<u32>; BLOCK_WORDS]) -> Self {
        (*block).into()
    }
}

impl<F: FieldExt> From<[Word<F>; BLOCK_WORDS]> for InputBlock<F> {
    fn from(block: [Word<F>; BLOCK_WORDS]) -> Self {
        InputBlock::Assigned(block)
    }
}

impl<F: FieldExt> From<&[Word<F>; BLOCK_WORDS]> for InputBlock<F> {
    fn from(block: &[Word<F>; BLOCK_WORDS]) -> Self {
        block.clone().into()
    }
}

impl<F: FieldExt> From<&[Word<F>]> for InputBlock<F> {
    fn from(block: &[Word<F>]) -> Self {
        let block: &[Word<F>; BLOCK_WORDS] = block.try_into().unwrap();
        Self::from(block)
    }
}

pub enum InputState<F: FieldExt> {
    Unassigned([Value<u32>; STATE_WORDS]),
    Assigned([Word<F>; STATE_WORDS]),
    Pi(Column<Instance>, Range<usize>),
    Iv,
}

impl<F: FieldExt> From<&[Value<u32>; STATE_WORDS]> for InputState<F> {
    fn from(state: &[Value<u32>; STATE_WORDS]) -> Self {
        InputState::Unassigned(*state)
    }
}

impl<F: FieldExt> From<[Word<F>; STATE_WORDS]> for InputState<F> {
    fn from(state: [Word<F>; STATE_WORDS]) -> Self {
        InputState::Assigned(state)
    }
}

impl<F: FieldExt> From<&[Word<F>; STATE_WORDS]> for InputState<F> {
    fn from(state: &[Word<F>; STATE_WORDS]) -> Self {
        state.clone().into()
    }
}

impl<F: FieldExt> From<(Column<Instance>, Range<usize>)> for InputState<F> {
    fn from((pi_col, pi_rows): (Column<Instance>, Range<usize>)) -> Self {
        InputState::Pi(pi_col, pi_rows)
    }
}

impl<F: FieldExt> InputState<F> {
    fn into_words(self) -> [Word<F>; STATE_WORDS] {
        match self {
            InputState::Assigned(state) => state,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CompressConfig<F: FieldExt, const BIT_COLS: usize> {
    pub(crate) int_col: Column<Advice>,
    pub(crate) bit_cols: Vec<Column<Advice>>,
    sigma_col: Column<Advice>,
    s0_offset: usize,
    s1_offset: usize,
    sum_operand_cols: Vec<Column<Advice>>,
    sum_hi_col: Column<Advice>,
    sum_lo_col: Column<Advice>,
    ch_maj_col: Column<Advice>,
    ch_maj_prev_col: Column<Advice>,
    ch_maj_operand_1_cols: Vec<Column<Advice>>,
    ch_maj_operand_2_cols: Vec<Column<Advice>>,
    ch_maj_operand_3_cols: Vec<Column<Advice>>,
    s_check_word_bits: Selector,
    s_pack_word_bits: Selector,
    s_modular_sum: Selector,
    s_sigma_lower_0: Selector,
    s_sigma_lower_1: Selector,
    s_sigma_upper_0: Selector,
    s_sigma_upper_1: Selector,
    s_ch: Selector,
    s_maj: Selector,
    _f: PhantomData<F>,
}

pub struct CompressChip<F: FieldExt, const BIT_COLS: usize> {
    config: CompressConfig<F, BIT_COLS>,
}

impl<F: FieldExt, const BIT_COLS: usize> ColumnCount for CompressChip<F, BIT_COLS> {
    fn num_cols() -> NumCols {
        NumCols {
            // Columns to store word bits, one column to store word `u32`s, and if the number of bit columns
            // necessitates, one column to store sigma values.
            advice_eq: BIT_COLS + 1 + Self::distinct_sigma_col() as usize,
            advice_neq: 0,
            fixed_eq: 1,
            fixed_neq: 0,
        }
    }
}

impl<F: FieldExt, const BIT_COLS: usize> Chip<F> for CompressChip<F, BIT_COLS> {
    type Config = CompressConfig<F, BIT_COLS>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const BIT_COLS: usize> CompressChip<F, BIT_COLS> {
    pub fn construct(config: CompressConfig<F, BIT_COLS>) -> Self {
        CompressChip { config }
    }

    // # Side Effects
    //
    // - First `CompressChip::num_cols().advice_eq` `advice` will be equality enabled.
    // - `fixed` will be constant (and equality) enabled.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: &[Column<Advice>],
        fixed: &Column<Fixed>,
    ) -> CompressConfig<F, BIT_COLS> {
        let num_advice = Self::num_cols().advice_eq;
        assert!(advice.len() >= num_advice);

        // We need at least one additional column to store the modular sum's `hi` component.
        assert!(BIT_COLS > MODULAR_SUM_OPERANDS);

        let ch_maj_bits_per_row = Self::ch_maj_bits_per_row();
        // Add two columns for running sum's "before" and "after" values.
        assert!(num_advice >= 3 * ch_maj_bits_per_row + 2);

        let advice = &advice[..num_advice];

        for col in advice {
            meta.enable_equality(*col);
        }
        // Fixed column will store sha256 round constants.
        meta.enable_constant(*fixed);

        let int_col = advice[0];
        let bit_cols = advice[1..BIT_COLS + 1].to_vec();

        let (sigma_col, s0_offset) = if Self::distinct_sigma_col() {
            (advice[BIT_COLS + 1], 0)
        } else {
            (int_col, 1)
        };
        let s1_offset = s0_offset + 1;

        let sum_operand_cols = bit_cols[..MODULAR_SUM_OPERANDS].to_vec();
        let sum_hi_col = bit_cols[MODULAR_SUM_OPERANDS];
        let sum_lo_col = int_col;

        let ch_maj_col = int_col;
        let mut ch_maj_cols = bit_cols.chunks(ch_maj_bits_per_row);
        let ch_maj_operand_1_cols = ch_maj_cols.next().unwrap().to_vec();
        let ch_maj_operand_2_cols = ch_maj_cols.next().unwrap().to_vec();
        let ch_maj_operand_3_cols = ch_maj_cols.next().unwrap().to_vec();
        let ch_maj_prev_col = ch_maj_cols.next().unwrap()[0];

        // Queries a word's 32 bits.
        let query_word_bits = |meta: &mut VirtualCells<'_, F>| -> Vec<Expression<F>> {
            AdviceIter::from(bit_cols.clone())
                .take(32)
                .map(|(offset, col)| meta.query_advice(col, Rotation(offset as i32)))
                .collect()
        };

        let s_check_word_bits = meta.selector();
        meta.create_gate("check_word_bits", |meta| {
            let s = meta.query_selector(s_check_word_bits);
            let mut bits = query_word_bits(meta);
            let bool_checks: Vec<Expression<F>> = bits.drain(..).map(bool_check).collect();
            Constraints::with_selector(s, bool_checks)
        });

        let s_pack_word_bits = meta.selector();
        meta.create_gate("pack_word_bits", |meta| {
            let s = meta.query_selector(s_pack_word_bits);
            let bits = query_word_bits(meta);
            let packed = pack_bits(bits);
            let int = meta.query_advice(int_col, Rotation::cur());
            [s * (int - packed)]
        });

        let s_modular_sum = meta.selector();
        meta.create_gate("modular_sum", |meta| {
            let s = meta.query_selector(s_modular_sum);

            // Query operands and compute their non-modular sum.
            let sum = sum_operand_cols
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .fold(Expression::Constant(F::zero()), |acc, x| acc + x);

            // Decompose the non-modular sum into two base-2^32 components; the low component is the
            // modular sum.
            let lo = meta.query_advice(sum_lo_col, Rotation::cur());
            let hi = meta.query_advice(sum_hi_col, Rotation::cur());
            let decomp = lo + hi * Expression::Constant(F::from(1 << 32));

            [s * (sum - decomp)]
        });

        // Returns `a xor b` for two bits `a` and `b`.
        #[inline]
        fn xor<F: FieldExt>((a, b): (Expression<F>, Expression<F>)) -> Expression<F> {
            // `a xor b = (a + b) - (a + a)b`
            let a_plus_b = a.clone() + b.clone();
            let a_plus_a = a.clone() + a;
            a_plus_b - a_plus_a * b
        }

        let s_sigma_lower_0 = meta.selector();
        meta.create_gate("sigma_lower_0", |meta| {
            let s = meta.query_selector(s_sigma_lower_0);

            let bits = query_word_bits(meta);

            let rotr7 = bits.iter().skip(7).chain(&bits).take(32).cloned();
            let rotr18 = bits.iter().skip(18).chain(&bits).take(32).cloned();
            let shr3 = bits
                .iter()
                .skip(3)
                .cloned()
                .chain(iter::repeat(Expression::Constant(F::zero())))
                .take(32);

            let sigma_bits = rotr7.zip(rotr18).map(xor).zip(shr3).map(xor).collect();
            let sigma_packed = pack_bits(sigma_bits);
            let sigma = meta.query_advice(sigma_col, Rotation(s0_offset as i32));

            [s * (sigma - sigma_packed)]
        });

        let s_sigma_lower_1 = meta.selector();
        meta.create_gate("sigma_lower_1", |meta| {
            let s = meta.query_selector(s_sigma_lower_1);

            let bits = query_word_bits(meta);

            let rotr17 = bits.iter().skip(17).chain(&bits).take(32).cloned();
            let rotr19 = bits.iter().skip(19).chain(&bits).take(32).cloned();
            let shr10 = bits
                .iter()
                .skip(10)
                .cloned()
                .chain(iter::repeat(Expression::Constant(F::zero())))
                .take(32);

            let sigma_bits = rotr17.zip(rotr19).map(xor).zip(shr10).map(xor).collect();
            let sigma_packed = pack_bits(sigma_bits);
            let sigma = meta.query_advice(sigma_col, Rotation(s1_offset as i32));

            [s * (sigma - sigma_packed)]
        });

        let s_sigma_upper_0 = meta.selector();
        meta.create_gate("sigma_upper_0", |meta| {
            let s = meta.query_selector(s_sigma_upper_0);

            let bits = query_word_bits(meta);

            let rotr2 = bits.iter().skip(2).chain(&bits).take(32).cloned();
            let rotr13 = bits.iter().skip(13).chain(&bits).take(32).cloned();
            let rotr22 = bits.iter().skip(22).chain(&bits).take(32).cloned();

            let sigma_bits = rotr2.zip(rotr13).map(xor).zip(rotr22).map(xor).collect();
            let sigma_packed = pack_bits(sigma_bits);
            let sigma = meta.query_advice(sigma_col, Rotation(s0_offset as i32));

            [s * (sigma - sigma_packed)]
        });

        let s_sigma_upper_1 = meta.selector();
        meta.create_gate("sigma_upper_1", |meta| {
            let s = meta.query_selector(s_sigma_upper_1);

            let bits = query_word_bits(meta);

            let rotr6 = bits.iter().skip(6).chain(&bits).take(32).cloned();
            let rotr11 = bits.iter().skip(11).chain(&bits).take(32).cloned();
            let rotr25 = bits.iter().skip(25).chain(&bits).take(32).cloned();

            let sigma_bits = rotr6.zip(rotr11).map(xor).zip(rotr25).map(xor).collect();
            let sigma_packed = pack_bits(sigma_bits);
            let sigma = meta.query_advice(sigma_col, Rotation(s1_offset as i32));

            [s * (sigma - sigma_packed)]
        });

        // Returns `ch(e, f, g) = e(f - g) + g` for bits `e, f, g`.
        #[inline]
        fn ch<F: FieldExt>(e: Expression<F>, f: Expression<F>, g: Expression<F>) -> Expression<F> {
            e * (f - g.clone()) + g
        }

        // Verfies one running sum iteration for the `ch` function.
        let s_ch = meta.selector();
        meta.create_gate("ch", |meta| {
            let s = meta.query_selector(s_ch);

            // Query `e, g, f` bits in the current row.
            let mut e_bits: Vec<Expression<F>> = ch_maj_operand_1_cols
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect();

            let mut f_bits: Vec<Expression<F>> = ch_maj_operand_2_cols
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect();

            let mut g_bits: Vec<Expression<F>> = ch_maj_operand_3_cols
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect();

            // Perform `ch` bitwise on this row's bits then pack.
            let ch_bits = e_bits
                .drain(..)
                .zip(f_bits.drain(..))
                .zip(g_bits.drain(..))
                .map(|((e_bit, f_bit), g_bit)| ch(e_bit, f_bit, g_bit))
                .collect();
            let ch_row = pack_bits(ch_bits);

            // Left-shift the previous row's running sum output then add this row's `ch` bits.
            let prev = meta.query_advice(ch_maj_prev_col, Rotation::cur());
            let shl = Expression::Constant(F::from(1 << ch_maj_bits_per_row));
            let new = prev * shl + ch_row;

            let ch = meta.query_advice(ch_maj_col, Rotation::cur());

            [s * (ch - new)]
        });

        // Returns `maj(a, b, c) = bc - (2bc - b - c)a` for bits `a, b, c`.
        #[inline]
        fn maj<F: FieldExt>(a: Expression<F>, b: Expression<F>, c: Expression<F>) -> Expression<F> {
            let bc = b.clone() * c.clone();
            let two_bc = Expression::Constant(F::from(2)) * bc.clone();
            bc - (two_bc - b - c) * a
        }

        // Verfies one running sum iteration for the `maj` function.
        let s_maj = meta.selector();
        meta.create_gate("maj", |meta| {
            let s = meta.query_selector(s_maj);

            // Query `a, b, c` bits in the current row.
            let mut a_bits: Vec<Expression<F>> = ch_maj_operand_1_cols
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect();

            let mut b_bits: Vec<Expression<F>> = ch_maj_operand_2_cols
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect();

            let mut c_bits: Vec<Expression<F>> = ch_maj_operand_3_cols
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect();

            // Perform `maj` bitwise on this row's bits then pack the resulting bits.
            let maj_bits = a_bits
                .drain(..)
                .zip(b_bits.drain(..))
                .zip(c_bits.drain(..))
                .map(|((a_bit, b_bit), c_bit)| maj(a_bit, b_bit, c_bit))
                .collect();
            let maj_row = pack_bits(maj_bits);

            // Left-shift the previous row's running sum output then add this row's `maj` bits.
            let prev = meta.query_advice(ch_maj_prev_col, Rotation::cur());
            let shl = Expression::Constant(F::from(1 << ch_maj_bits_per_row));
            let new = prev * shl + maj_row;

            let maj = meta.query_advice(ch_maj_col, Rotation::cur());

            [s * (maj - new)]
        });

        CompressConfig {
            int_col,
            bit_cols,
            sigma_col,
            s0_offset,
            s1_offset,
            sum_operand_cols,
            sum_hi_col,
            sum_lo_col,
            ch_maj_col,
            ch_maj_prev_col,
            ch_maj_operand_1_cols,
            ch_maj_operand_2_cols,
            ch_maj_operand_3_cols,
            s_check_word_bits,
            s_pack_word_bits,
            s_modular_sum,
            s_sigma_lower_0,
            s_sigma_lower_1,
            s_sigma_upper_0,
            s_sigma_upper_1,
            s_ch,
            s_maj,
            _f: PhantomData,
        }
    }

    pub fn assign_word(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        offset: &mut usize,
        word: &Value<u32>,
        pack: bool,
    ) -> Result<Word<F>, Error> {
        self.config.s_check_word_bits.enable(region, *offset)?;

        let bits = AdviceIter::new(*offset, self.config.bit_cols.clone())
            .take(32)
            .enumerate()
            .map(|(i, (offset, col))| {
                region
                    .assign_advice(
                        || format!("{} bit_{}", annotation, i),
                        col,
                        offset,
                        || word.map(|word| Bit(word >> i & 1 == 1)),
                    )
                    .map(Some)
            })
            .collect::<Result<Vec<Option<AssignedBit<F>>>, Error>>()
            .map(|bits| bits.try_into().unwrap())?;

        let int = if pack {
            self.config.s_pack_word_bits.enable(region, *offset)?;
            let packed = region.assign_advice(
                || format!("{} int", annotation),
                self.config.int_col,
                *offset,
                || word.map(U32),
            )?;
            Some(packed)
        } else {
            None
        };

        let word = Word {
            bits,
            int,
            offset: *offset,
        };
        *offset += Self::word_rows();
        Ok(word)
    }

    fn assign_pi_word(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        offset: &mut usize,
        pi_col: Column<Instance>,
        mut pi_rows: Range<usize>,
    ) -> Result<Word<F>, Error> {
        assert_eq!(pi_rows.end - pi_rows.start, WORD_PUB_INPUTS);

        self.config.s_check_word_bits.enable(region, *offset)?;
        self.config.s_pack_word_bits.enable(region, *offset)?;

        let bits = AdviceIter::new(*offset, self.config.bit_cols.clone())
            .take(32)
            .enumerate()
            .map(|(i, (offset, col))| {
                region
                    .assign_advice_from_instance(
                        || format!("{} pi bit_{}", annotation, i),
                        pi_col,
                        pi_rows.next().unwrap(),
                        col,
                        offset,
                    )
                    .map(convert_assigned_f)
                    .map(Some)
            })
            .collect::<Result<Vec<Option<AssignedBit<F>>>, Error>>()
            .map(|bits| bits.try_into().unwrap())?;

        let int = region
            .assign_advice_from_instance(
                || format!("{} pi int", annotation),
                pi_col,
                pi_rows.next().unwrap(),
                self.config.int_col,
                *offset,
            )
            .map(convert_assigned_f)?;

        let word = Word {
            bits,
            int: Some(int),
            offset: *offset,
        };
        *offset += Self::word_rows();
        Ok(word)
    }

    fn assign_input_state(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        state: &[Value<u32>; STATE_WORDS],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        state
            .iter()
            .enumerate()
            .map(|(i, word)| {
                self.assign_word(region, &format!("state_in[{}]", i), offset, word, true)
            })
            .collect::<Result<Vec<Word<F>>, Error>>()
            .map(|state| state.try_into().unwrap())
    }

    fn assign_pi_input_state(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        pi_col: Column<Instance>,
        pi_rows: Range<usize>,
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        assert_eq!(pi_rows.end - pi_rows.start, STATE_PUB_INPUTS);
        pi_rows
            .step_by(33)
            .enumerate()
            .map(|(i, first_pi_row)| {
                self.assign_pi_word(
                    region,
                    &format!("state_in[{}]", i),
                    offset,
                    pi_col,
                    first_pi_row..first_pi_row + WORD_PUB_INPUTS,
                )
            })
            .collect::<Result<Vec<Word<F>>, Error>>()
            .map(|state| state.try_into().unwrap())
    }

    fn assign_iv(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        IV.iter()
            .enumerate()
            .map(|(word_index, word)| {
                let annotation = format!("iv word_{}", word_index);

                let bits = AdviceIter::new(*offset, self.config.bit_cols.clone())
                    .take(32)
                    .enumerate()
                    .map(|(bit_index, (offset, col))| {
                        region
                            .assign_advice_from_constant(
                                || format!("{} bit_{}", annotation, bit_index),
                                col,
                                offset,
                                Bit(*word >> bit_index & 1 == 1),
                            )
                            .map(Some)
                    })
                    .collect::<Result<Vec<Option<AssignedBit<F>>>, Error>>()?
                    .try_into()
                    .unwrap();

                let int = region
                    .assign_advice_from_constant(
                        || format!("{} int", annotation),
                        self.config.int_col,
                        *offset,
                        U32(*word),
                    )
                    .map(Some)?;

                let word = Word {
                    bits,
                    int,
                    offset: *offset,
                };
                *offset += Self::word_rows();
                Ok(word)
            })
            .collect::<Result<Vec<Word<F>>, Error>>()
            .map(|state| state.try_into().unwrap())
    }

    // Addition of `u32`s `mod 2^32`; most provide at least two and at most 5 operands to sum.
    fn modular_sum(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        offset: &mut usize,
        u32s: &[&AssignedU32<F>],
        constant: Option<u32>,
        assign_bits: bool,
    ) -> Result<Word<F>, Error> {
        let num_operands = u32s.len() + constant.is_some() as usize;
        assert!(num_operands >= 2, "cannot sum fewer than 2 values");
        assert!(
            num_operands <= MODULAR_SUM_OPERANDS,
            "cannot sum more than 5 values"
        );

        self.config.s_modular_sum.enable(region, *offset)?;

        let annotation = format!("{} modular_sum", annotation);

        // Copy and assign operands.
        let mut operands = Vec::<AssignedCell<U32, F>>::with_capacity(num_operands);
        let mut i = 0;
        for int in u32s {
            let operand = int.copy_advice(
                || format!("{} copy operands[{}]", annotation, i),
                region,
                self.config.sum_operand_cols[i],
                *offset,
            )?;
            operands.push(operand);
            i += 1;
        }
        if let Some(constant) = constant {
            let constant = region.assign_advice_from_constant(
                || format!("{} assign constant operands[{}]", annotation, i),
                self.config.sum_operand_cols[i],
                *offset,
                U32(constant),
            )?;
            operands.push(constant);
            i += 1;
        }
        let num_zeros = MODULAR_SUM_OPERANDS - num_operands;
        for _ in 0..num_zeros {
            let zero = region.assign_advice_from_constant(
                || format!("{} addition zero operands[{}]", annotation, i),
                self.config.sum_operand_cols[i],
                *offset,
                U32(0),
            )?;
            operands.push(zero);
            i += 1;
        }

        // Assign `sum`'s high and low parts; low is assigned in next row.
        let sum = operands
            .drain(..)
            .fold(Value::known(0u64), |acc, x| acc + x.value().map(u64::from));
        region.assign_advice(
            || format!("{} hi", annotation),
            self.config.sum_hi_col,
            *offset,
            || sum.map(|sum| U32((sum >> 32) as u32)),
        )?;
        let lo = region.assign_advice(
            || format!("{} lo", annotation),
            self.config.sum_lo_col,
            *offset,
            || sum.map(|sum| U32(sum as u32)),
        )?;

        let word = if assign_bits {
            *offset += 1;

            self.config.s_pack_word_bits.enable(region, *offset)?;

            let sum_value = lo.value().map(u32::from);

            let bits = AdviceIter::new(*offset, self.config.bit_cols.clone())
                .take(32)
                .enumerate()
                .map(|(i, (offset, col))| {
                    region
                        .assign_advice(
                            || format!("{} sum bit_{}", annotation, i),
                            col,
                            offset,
                            || sum_value.map(|sum| Bit(sum >> i & 1 == 1)),
                        )
                        .map(Some)
                })
                .collect::<Result<Vec<Option<AssignedBit<F>>>, Error>>()
                .map(|bits| bits.try_into().unwrap())?;

            let sum = lo.copy_advice(
                || format!("{} copy sum = lo", annotation),
                region,
                self.config.int_col,
                *offset,
            )?;

            let word = Word {
                bits,
                int: Some(sum),
                offset: *offset,
            };
            *offset += Self::word_rows();
            word
        } else {
            let word = Word {
                bits: vec![None; 32].try_into().unwrap(),
                int: Some(lo),
                offset: *offset,
            };
            *offset += 1;
            word
        };

        Ok(word)
    }

    // Returns an `AssignedU32` rather than a `Word` as the the sigma value will only be used in
    // modular `u32` addition.
    fn sigma_lower_0(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        word: &Word<F>,
    ) -> Result<AssignedU32<F>, Error> {
        assert!(
            word.bits.iter().all(|bit| bit.is_some()),
            "word contains less than 32 bits",
        );

        self.config.s_sigma_lower_0.enable(region, word.offset)?;

        region.assign_advice(
            || format!("{} s0", annotation),
            self.config.sigma_col,
            word.offset + self.config.s0_offset,
            || {
                word.rotr(7)
                    .value_u32()
                    .zip(word.rotr(18).value_u32())
                    .zip(word.shr(3).value_u32())
                    .map(|((x, y), z)| U32((x ^ y) ^ z))
            },
        )
    }

    // Returns an `AssignedU32` rather than a `Word` as the the sigma value will only be used in
    // modular `u32` addition.
    fn sigma_lower_1(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        word: &Word<F>,
    ) -> Result<AssignedU32<F>, Error> {
        assert!(
            word.bits.iter().all(|bit| bit.is_some()),
            "word contains less than 32 bits",
        );

        self.config.s_sigma_lower_1.enable(region, word.offset)?;

        region.assign_advice(
            || format!("{} s1", annotation),
            self.config.sigma_col,
            word.offset + self.config.s1_offset,
            || {
                word.rotr(17)
                    .value_u32()
                    .zip(word.rotr(19).value_u32())
                    .zip(word.shr(10).value_u32())
                    .map(|((x, y), z)| U32((x ^ y) ^ z))
            },
        )
    }

    // Returns an `AssignedU32` rather than a `Word` as the the sigma value will only be used in
    // modular `u32` addition.
    fn sigma_upper_0(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        a: &Word<F>,
    ) -> Result<AssignedU32<F>, Error> {
        assert!(
            a.bits.iter().all(|bit| bit.is_some()),
            "`a` contains less than 32 bits",
        );

        self.config.s_sigma_upper_0.enable(region, a.offset)?;

        region.assign_advice(
            || format!("{} S0", annotation),
            self.config.sigma_col,
            a.offset + self.config.s0_offset,
            || {
                a.rotr(2)
                    .value_u32()
                    .zip(a.rotr(13).value_u32())
                    .zip(a.rotr(22).value_u32())
                    .map(|((x, y), z)| U32((x ^ y) ^ z))
            },
        )
    }

    // Returns an `AssignedU32` rather than a `Word` as the the sigma value will only be used in
    // modular `u32` addition.
    fn sigma_upper_1(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        e: &Word<F>,
    ) -> Result<AssignedU32<F>, Error> {
        assert!(
            e.bits.iter().all(|bit| bit.is_some()),
            "`e` contains less than 32 bits",
        );

        self.config.s_sigma_upper_1.enable(region, e.offset)?;

        region.assign_advice(
            || format!("{} S1", annotation),
            self.config.sigma_col,
            e.offset + self.config.s1_offset,
            || {
                e.rotr(6)
                    .value_u32()
                    .zip(e.rotr(11).value_u32())
                    .zip(e.rotr(25).value_u32())
                    .map(|((x, y), z)| U32((x ^ y) ^ z))
            },
        )
    }

    // Performs `ch` on three state words `e, f, g`.
    //
    // Returns an `AssignedU32` (rather than a `Word`) because the returned value will only be used
    // in modular `u32` addition (which does not utilize the 32 assigned `Word` bits).
    fn ch(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        offset: &mut usize,
        e: &Word<F>,
        f: &Word<F>,
        g: &Word<F>,
    ) -> Result<AssignedU32<F>, Error> {
        assert!(
            e.bits.iter().all(|bit| bit.is_some()),
            "`e` contains less than 32 bits"
        );
        assert!(
            f.bits.iter().all(|bit| bit.is_some()),
            "`f` contains less than 32 bits"
        );
        assert!(
            g.bits.iter().all(|bit| bit.is_some()),
            "`g` contains less than 32 bits"
        );

        let bits_per_row = Self::ch_maj_bits_per_row();

        // Initialize `ch`'s running sum to zero.
        let mut ch = region.assign_advice_from_constant(
            || format!("{} ch_prev_{} = zero", annotation, Self::ch_maj_rows() - 1),
            self.config.ch_maj_prev_col,
            *offset,
            U32(0),
        )?;

        for (chunk_index, ((e_bits, f_bits), g_bits)) in e
            .bits_unchecked()
            .chunks(bits_per_row)
            .zip(f.bits_unchecked().chunks(bits_per_row))
            .zip(g.bits_unchecked().chunks(bits_per_row))
            .enumerate()
            .rev()
        {
            self.config.s_ch.enable(region, *offset)?;

            // Apply `ch` to the bits in this row.
            let mut ch_row = Value::known(0u32);
            let mut bit_index = chunk_index * bits_per_row;

            for (i, (((e_bit, e_col), (f_bit, f_col)), (g_bit, g_col))) in e_bits
                .iter()
                .zip(&self.config.ch_maj_operand_1_cols)
                .zip(f_bits.iter().zip(&self.config.ch_maj_operand_2_cols))
                .zip(g_bits.iter().zip(&self.config.ch_maj_operand_3_cols))
                .enumerate()
            {
                let e_bit = e_bit.copy_advice(
                    || format!("{} copy e_bits[{}]", annotation, bit_index),
                    region,
                    *e_col,
                    *offset,
                )?;
                let f_bit = f_bit.copy_advice(
                    || format!("{} copy f_bits[{}]", annotation, bit_index),
                    region,
                    *f_col,
                    *offset,
                )?;
                let g_bit = g_bit.copy_advice(
                    || format!("{} copy g_bits[{}]", annotation, bit_index),
                    region,
                    *g_col,
                    *offset,
                )?;

                ch_row = ch_row
                    .zip(e_bit.value().map(bool::from))
                    .zip(f_bit.value().map(bool::from))
                    .zip(g_bit.value().map(bool::from))
                    .map(|(((ch_row, e), f), g)| {
                        let ch_bit = (e & f) ^ (!e & g);
                        ch_row + ((ch_bit as u32) << i)
                    });

                bit_index += 1;
            }

            // Left-shift `ch` running sum then add this rows's `ch`.
            ch = region.assign_advice(
                || format!("{} ch_{}", annotation, chunk_index),
                self.config.ch_maj_col,
                *offset,
                || {
                    ch.value()
                        .map(u32::from)
                        .zip(ch_row)
                        .map(|(ch_prev, ch_row)| U32((ch_prev << bits_per_row) + ch_row))
                },
            )?;

            *offset += 1;

            // If this is not the last chunk of bits, copy the running sum into the next row.
            if chunk_index != 0 {
                ch.copy_advice(
                    || {
                        format!(
                            "{} copy ch_prev_{} = ch_{}",
                            annotation,
                            chunk_index - 1,
                            chunk_index
                        )
                    },
                    region,
                    self.config.ch_maj_prev_col,
                    *offset,
                )?;
            }
        }

        Ok(ch)
    }

    // Performs `maj` on three state words `a, b, c`.
    //
    // Returns an `AssignedU32` (rather than a `Word`) because the returned value will only be used
    // in modular `u32` addition (which does not utilize the 32 assigned `Word` bits).
    fn maj(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        offset: &mut usize,
        a: &Word<F>,
        b: &Word<F>,
        c: &Word<F>,
    ) -> Result<AssignedU32<F>, Error> {
        assert!(
            a.bits.iter().all(|bit| bit.is_some()),
            "`a` contains less than 32 bits"
        );
        assert!(
            b.bits.iter().all(|bit| bit.is_some()),
            "`b` contains less than 32 bits"
        );
        assert!(
            c.bits.iter().all(|bit| bit.is_some()),
            "`c` contains less than 32 bits"
        );

        let bits_per_row = Self::ch_maj_bits_per_row();

        // Initialize `ch`'s running sum to zero.
        let mut maj = region.assign_advice_from_constant(
            || format!("{} maj_prev_{} = zero", annotation, Self::ch_maj_rows() - 1),
            self.config.ch_maj_prev_col,
            *offset,
            U32(0),
        )?;

        for (chunk_index, ((a_bits, b_bits), c_bits)) in a
            .bits_unchecked()
            .chunks(bits_per_row)
            .zip(b.bits_unchecked().chunks(bits_per_row))
            .zip(c.bits_unchecked().chunks(bits_per_row))
            .enumerate()
            .rev()
        {
            self.config.s_maj.enable(region, *offset)?;

            // Apply `ch` to the bits in this row.
            let mut maj_row = Value::known(0u32);
            let mut bit_index = chunk_index * bits_per_row;

            for (i, (((a_bit, a_col), (b_bit, b_col)), (c_bit, c_col))) in a_bits
                .iter()
                .zip(&self.config.ch_maj_operand_1_cols)
                .zip(b_bits.iter().zip(&self.config.ch_maj_operand_2_cols))
                .zip(c_bits.iter().zip(&self.config.ch_maj_operand_3_cols))
                .enumerate()
            {
                let a_bit = a_bit.copy_advice(
                    || format!("{} copy a_bits[{}]", annotation, bit_index),
                    region,
                    *a_col,
                    *offset,
                )?;
                let b_bit = b_bit.copy_advice(
                    || format!("{} copy b_bits[{}]", annotation, bit_index),
                    region,
                    *b_col,
                    *offset,
                )?;
                let c_bit = c_bit.copy_advice(
                    || format!("{} copy c_bits[{}]", annotation, bit_index),
                    region,
                    *c_col,
                    *offset,
                )?;

                maj_row = maj_row
                    .zip(a_bit.value().map(bool::from))
                    .zip(b_bit.value().map(bool::from))
                    .zip(c_bit.value().map(bool::from))
                    .map(|(((maj_row, a), b), c)| {
                        let maj_bit = (a & b) ^ (a & c) ^ (b & c);
                        maj_row + ((maj_bit as u32) << i)
                    });

                bit_index += 1;
            }

            // Left-shift `maj` running sum then add this rows's `maj`.
            maj = region.assign_advice(
                || format!("{} maj_{}", annotation, chunk_index),
                self.config.ch_maj_col,
                *offset,
                || {
                    maj.value()
                        .map(u32::from)
                        .zip(maj_row)
                        .map(|(maj_prev, maj_row)| U32((maj_prev << bits_per_row) + maj_row))
                },
            )?;

            *offset += 1;

            // If this is not the last chunk of bits, copy the running sum into the next row.
            if chunk_index != 0 {
                maj.copy_advice(
                    || {
                        format!(
                            "{} copy maj_prev_{} = maj_{}",
                            annotation,
                            chunk_index - 1,
                            chunk_index
                        )
                    },
                    region,
                    self.config.ch_maj_prev_col,
                    *offset,
                )?;
            }
        }

        Ok(maj)
    }

    pub fn compress(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        block: &InputBlock<F>,
        state: &InputState<F>,
        block_index: usize,
        is_last_block: bool,
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        let annotation = format!("compress block_{}", block_index);
        let offset_start = *offset;

        let mut w = Vec::<Word<F>>::with_capacity(NUM_ROUNDS);

        // Assign or copy the input block; set the first message schedule words to the input block.
        match block {
            InputBlock::Unassigned(block) => {
                for (i, word) in block.iter().enumerate() {
                    let word = self.assign_word(
                        region,
                        &format!("{} block_word_{}", annotation, i),
                        offset,
                        word,
                        true,
                    )?;
                    w.push(word);
                }
            }
            // Input block must be assigned in the same region as `CompressChip::compress`.
            InputBlock::Assigned(block) => {
                assert!(block.iter().all(|word| {
                    word.bits.iter().all(|bit| bit.is_some())
                        && word.int.is_some()
                        && word.offset < offset_start
                }),);
                w.extend_from_slice(block);
            }
        };

        // Assign the remaining message schedule words.
        for i in BLOCK_WORDS..NUM_ROUNDS {
            let annotation = format!("{} w[{}]", annotation, i);
            let s0 = self.sigma_lower_0(region, &annotation, &w[i - 15])?;
            let s1 = self.sigma_lower_1(region, &annotation, &w[i - 2])?;
            let wi = self.modular_sum(
                region,
                &annotation,
                offset,
                &[
                    w[i - 16]
                        .int
                        .as_ref()
                        .expect("`w[i-16]`'s `u32` should be set"),
                    &s0,
                    w[i - 7]
                        .int
                        .as_ref()
                        .expect("`w[i-7]`'s `u32` should be set"),
                    &s1,
                ],
                None,
                true,
            )?;
            w.push(wi);
        }

        let state = match state {
            InputState::Unassigned(state) => self.assign_input_state(region, offset, state)?,
            // Input state must be assigned in the same region as `CompressChip::compress`.
            InputState::Assigned(state) => {
                assert!(state.iter().all(|word| {
                    word.bits.iter().all(|bit| bit.is_some())
                        && word.int.is_some()
                        && word.offset < offset_start
                }),);
                state.clone()
            }
            InputState::Pi(pi_col, pi_rows) => {
                self.assign_pi_input_state(region, offset, *pi_col, pi_rows.clone())?
            }
            InputState::Iv => self.assign_iv(region, offset)?,
        };

        let [a_in, b_in, c_in, d_in, e_in, f_in, g_in, h_in] = state.clone();
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;

        // Mutate the input state.
        for round_index in 0..64 {
            let annotation = format!("{} round_{}", annotation, round_index);

            let s0 = self.sigma_upper_0(region, &annotation, &a)?;
            let s1 = self.sigma_upper_1(region, &annotation, &e)?;

            let ch = self.ch(region, &annotation, offset, &e, &f, &g)?;
            let maj = self.maj(region, &annotation, offset, &a, &b, &c)?;

            let tmp1 = self
                .modular_sum(
                    region,
                    &format!("{} tmp1", annotation),
                    offset,
                    &[
                        h.int.as_ref().expect("`h`'s `u32` should be set"),
                        &s1,
                        &ch,
                        w[round_index]
                            .int
                            .as_ref()
                            .expect("`w[i]`'s `u32` should be set"),
                    ],
                    Some(ROUND_CONSTANTS[round_index]),
                    false,
                )
                .map(|tmp1| tmp1.int.expect("`tmp1`'s `u32` should be set"))?;

            let tmp2 = self
                .modular_sum(
                    region,
                    &format!("{} tmp2", annotation),
                    offset,
                    &[&s0, &maj],
                    None,
                    false,
                )
                .map(|tmp2| tmp2.int.expect("`tmp2`'s `u32` should be set"))?;

            let e_new = self.modular_sum(
                region,
                &format!("{} e_new", annotation),
                offset,
                &[d.int.as_ref().expect("`d`'s `u32` should be set"), &tmp1],
                None,
                true,
            )?;
            let a_new = self.modular_sum(
                region,
                &format!("{} a_new", annotation),
                offset,
                &[&tmp1, &tmp2],
                None,
                true,
            )?;

            h = g;
            g = f;
            f = e;
            e = e_new;
            d = c;
            c = b;
            b = a;
            a = a_new;
        }

        // If this is the last block of a multi-block preimage, don't assign the output state words'
        // bits.
        let assign_output_bits = !is_last_block;

        // Add last round's state to input state.
        a = self.modular_sum(
            region,
            &format!("{} a_out", annotation),
            offset,
            &[
                a_in.int.as_ref().expect("`a_in`'s `u32` should be set"),
                a.int.as_ref().expect("`a_last`'s `u32` should be set"),
            ],
            None,
            assign_output_bits,
        )?;

        b = self.modular_sum(
            region,
            &format!("{} b_out", annotation),
            offset,
            &[
                b_in.int.as_ref().expect("`b_in`'s `u32` should be set"),
                b.int.as_ref().expect("`b_last`'s `u32` should be set"),
            ],
            None,
            assign_output_bits,
        )?;

        c = self.modular_sum(
            region,
            &format!("{} c_out", annotation),
            offset,
            &[
                c_in.int.as_ref().expect("`c_in`'s `u32` should be set"),
                c.int.as_ref().expect("`c_last`'s `u32` should be set"),
            ],
            None,
            assign_output_bits,
        )?;

        d = self.modular_sum(
            region,
            &format!("{} d_out", annotation),
            offset,
            &[
                d_in.int.as_ref().expect("`d_in`'s `u32` should be set"),
                d.int.as_ref().expect("`d_last`'s `u32` should be set"),
            ],
            None,
            assign_output_bits,
        )?;

        e = self.modular_sum(
            region,
            &format!("{} e_out", annotation),
            offset,
            &[
                e_in.int.as_ref().expect("`e_in`'s `u32` should be set"),
                e.int.as_ref().expect("`e_last`'s `u32` should be set"),
            ],
            None,
            assign_output_bits,
        )?;

        f = self.modular_sum(
            region,
            &format!("{} f_out", annotation),
            offset,
            &[
                f_in.int.as_ref().expect("`f_in`'s `u32` should be set"),
                f.int.as_ref().expect("`f_last`'s `u32` should be set"),
            ],
            None,
            assign_output_bits,
        )?;

        g = self.modular_sum(
            region,
            &format!("{} g_out", annotation),
            offset,
            &[
                g_in.int.as_ref().expect("`g_in`'s `u32` should be set"),
                g.int.as_ref().expect("`g_last`'s `u32` should be set"),
            ],
            None,
            assign_output_bits,
        )?;

        h = self.modular_sum(
            region,
            &format!("{} h_out", annotation),
            offset,
            &[
                h_in.int.as_ref().expect("`h_in`'s `u32` should be set"),
                h.int.as_ref().expect("`h_last`'s `u32` should be set"),
            ],
            None,
            assign_output_bits,
        )?;

        Ok([a, b, c, d, e, f, g, h])
    }

    pub fn assign_padding(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        unpadded_preimage_word_len: usize,
    ) -> Result<Vec<Word<F>>, Error> {
        get_padding(unpadded_preimage_word_len)
            .iter()
            .enumerate()
            .map(|(word_index, word)| {
                let annotation = format!("padding word_{}", word_index);

                let bits = AdviceIter::new(*offset, self.config.bit_cols.clone())
                    .take(32)
                    .enumerate()
                    .map(|(bit_index, (offset, col))| {
                        region
                            .assign_advice_from_constant(
                                || format!("{} bit_{}", annotation, bit_index),
                                col,
                                offset,
                                Bit(*word >> bit_index & 1 == 1),
                            )
                            .map(Some)
                    })
                    .collect::<Result<Vec<Option<AssignedBit<F>>>, Error>>()
                    .map(|bits| bits.try_into().unwrap())?;

                let int = region
                    .assign_advice_from_constant(
                        || format!("{} int", annotation),
                        self.config.int_col,
                        *offset,
                        U32(*word),
                    )
                    .map(Some)?;

                let word = Word {
                    bits,
                    int,
                    offset: *offset,
                };
                *offset += Self::word_rows();
                Ok(word)
            })
            .collect()
    }

    pub fn hash(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        blocks: &[InputBlock<F>],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        let num_blocks = blocks.len();
        assert_ne!(num_blocks, 0);
        let last_block_index = num_blocks - 1;

        let mut state = InputState::Iv;
        for (i, block) in blocks.iter().enumerate() {
            let is_last_block = i == last_block_index;
            state = self
                .compress(region, offset, block, &state, i, is_last_block)?
                .into();
        }
        Ok(state.into_words())
    }

    #[inline]
    pub fn hash_unassigned(
        &self,
        mut layouter: impl Layouter<F>,
        blocks: &[[Value<u32>; BLOCK_WORDS]],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        layouter.assign_region(
            || "sha256",
            |mut region| {
                let mut offset = 0;
                let blocks: Vec<InputBlock<F>> = blocks.iter().map(InputBlock::from).collect();
                self.hash(&mut region, &mut offset, &blocks)
            },
        )
    }

    #[inline]
    const fn distinct_sigma_col() -> bool {
        Self::word_rows() < 3
    }

    #[inline]
    pub const fn word_rows() -> usize {
        32 / BIT_COLS + ((32 % BIT_COLS != 0) as usize)
    }

    #[inline]
    pub const fn state_rows() -> usize {
        STATE_WORDS * Self::word_rows()
    }

    #[inline]
    const fn sum_rows() -> usize {
        1
    }

    #[inline]
    const fn ch_maj_bits_per_row() -> usize {
        match BIT_COLS {
            8 => 2,
            16 => 4,
            _ => unimplemented!(),
        }
    }

    #[inline]
    const fn ch_maj_rows() -> usize {
        32 / Self::ch_maj_bits_per_row()
    }

    // Number of rows consumed during single-block compression; returned number of rows does not
    // include input state assignment.
    pub const fn compress_rows() -> usize {
        let word_rows = Self::word_rows();
        let sum_rows = Self::sum_rows();
        let sum_with_decomp_rows = sum_rows + word_rows;
        let ch_maj_rows = Self::ch_maj_rows();

        let input_block_rows = BLOCK_WORDS * word_rows;
        let rem_msg_sched_rows = (NUM_ROUNDS - BLOCK_WORDS) * sum_with_decomp_rows;
        let round_rows = 2 * ch_maj_rows + 2 * sum_rows + 2 * sum_with_decomp_rows;
        let add_states_rows = STATE_WORDS * sum_rows;

        input_block_rows + rem_msg_sched_rows + NUM_ROUNDS * round_rows + add_states_rows
    }

    #[inline]
    pub const fn hash_rows(num_blocks: usize) -> usize {
        num_blocks * (Self::compress_rows() + Self::state_rows())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};

    use crate::{CircuitSize, ColumnBuilder};

    #[test]
    fn test_compress_chip() {
        // Configures the number blocks in the padded preimage.
        const NUM_BLOCKS: usize = 2;

        // Configures the number of advice columns in which to assign bits.
        const BIT_COLS: usize = 16;

        type CompressChip = super::CompressChip<Fp, BIT_COLS>;
        type CompressConfig = super::CompressConfig<Fp, BIT_COLS>;

        #[derive(Clone)]
        struct MyCircuit {
            blocks: [[Value<u32>; BLOCK_WORDS]; NUM_BLOCKS],
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    blocks: [[Value::unknown(); BLOCK_WORDS]; 2],
                }
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let (advice, _, fixed, _) = ColumnBuilder::new()
                    .with_chip::<CompressChip>()
                    .create_columns(meta);
                CompressChip::configure(meta, &advice, &fixed[0])
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let chip = CompressChip::construct(config);

                // Test sub-regions.
                layouter.assign_region(
                    || "test assign_word",
                    |mut region| {
                        let mut offset = 0;

                        let word_value = Value::known(0xafbc10ff);

                        let word_unpacked = chip.assign_word(
                            &mut region,
                            "unpacked",
                            &mut offset,
                            &word_value,
                            false,
                        )?;

                        assert_eq!(offset, CompressChip::word_rows());
                        assert_eq!(word_unpacked.offset, 0);
                        assert!(word_unpacked.bits.iter().all(|bit| bit.is_some()));
                        assert!(word_unpacked.int.is_none());

                        let offset_before = offset;

                        let word_packed = chip.assign_word(
                            &mut region,
                            "packed",
                            &mut offset,
                            &word_value,
                            true,
                        )?;

                        assert_eq!(offset - offset_before, CompressChip::word_rows());
                        assert_eq!(word_packed.offset, offset_before);
                        assert!(word_packed.bits.iter().all(|bit| bit.is_some()));
                        assert!(word_packed.int.is_some());

                        word_unpacked
                            .value_u32()
                            .zip(word_packed.value_u32())
                            .zip(word_value)
                            .assert_if_known(|((unpacked, packed), expected)| {
                                unpacked == expected && unpacked == packed
                            });

                        for (bit_1, bit_2) in word_unpacked
                            .bits_unchecked()
                            .iter()
                            .zip(word_packed.bits_unchecked())
                        {
                            bit_1
                                .value()
                                .zip(bit_2.value())
                                .assert_if_known(|(bit_1, bit_2)| {
                                    bool::from(*bit_1) == bool::from(*bit_2)
                                });
                        }

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test modular_add",
                    |mut region| {
                        let mut offset = 0;

                        let a_value = Value::known(0xff00ff00);
                        let b_value = Value::known(0x00ff00ff);
                        let c_value = Value::known(0xabcdef00);
                        let constant = 0x11111111;

                        let sum_rows = CompressChip::sum_rows();

                        let a = region.assign_advice(
                            || "a",
                            chip.config.sum_operand_cols[0],
                            offset,
                            || a_value.map(U32),
                        )?;
                        let b = region.assign_advice(
                            || "b",
                            chip.config.sum_operand_cols[1],
                            offset,
                            || b_value.map(U32),
                        )?;
                        let c = region.assign_advice(
                            || "c",
                            chip.config.sum_operand_cols[2],
                            offset,
                            || c_value.map(U32),
                        )?;
                        offset += 1;

                        // Test without constant.
                        let offset_before = offset;
                        let sum = chip.modular_sum(
                            &mut region,
                            "sum_1",
                            &mut offset,
                            &[&a, &b, &c],
                            None,
                            false,
                        )?;

                        assert_eq!(offset - offset_before, sum_rows);
                        assert_eq!(sum.offset, offset_before);
                        assert!(sum.int.is_some() && sum.bits.iter().all(|bit| bit.is_none()));
                        let sum_expected = a_value + b_value + c_value;
                        sum.value_u32()
                            .zip(sum_expected)
                            .assert_if_known(|(sum, expected)| sum == expected);

                        // Test with constant.
                        let offset_before = offset;
                        let sum = chip.modular_sum(
                            &mut region,
                            "sum_2",
                            &mut offset,
                            &[&a, &b, &c],
                            Some(constant),
                            false,
                        )?;
                        assert_eq!(offset - offset_before, sum_rows);
                        assert_eq!(sum.offset, offset_before);
                        assert!(sum.int.is_some() && sum.bits.iter().all(|bit| bit.is_none()));
                        let sum_expected = sum_expected + Value::known(constant);
                        sum.value_u32()
                            .zip(sum_expected)
                            .assert_if_known(|(sum, expected)| sum == expected);

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test sigma_lower",
                    |mut region| {
                        let mut offset = 0;

                        let word_value = Value::known(0xfa01ff50);

                        let word =
                            chip.assign_word(&mut region, "word", &mut offset, &word_value, true)?;

                        let s0 = chip.sigma_lower_0(&mut region, "s0", &word)?;

                        let s0_expected = word_value
                            .map(|word| word.rotate_right(7) ^ word.rotate_right(18) ^ (word >> 3));

                        s0.value()
                            .zip(s0_expected)
                            .assert_if_known(|(s0, expected)| u32::from(*s0) == *expected);

                        let s1 = chip.sigma_lower_1(&mut region, "s1", &word)?;

                        let s1_expected = word_value.map(|word| {
                            word.rotate_right(17) ^ word.rotate_right(19) ^ (word >> 10)
                        });

                        s1.value()
                            .zip(s1_expected)
                            .assert_if_known(|(s1, expected)| u32::from(*s1) == *expected);

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test sigma_upper",
                    |mut region| {
                        let mut offset = 0;

                        let word_value = Value::known(0xfa01ff50);

                        let word =
                            chip.assign_word(&mut region, "word", &mut offset, &word_value, true)?;

                        let s0 = chip.sigma_upper_0(&mut region, "S0", &word)?;

                        s0.value().zip(word_value).assert_if_known(|(s0, word)| {
                            let expected = word.rotate_right(2)
                                ^ word.rotate_right(13)
                                ^ word.rotate_right(22);
                            u32::from(*s0) == expected
                        });

                        let s1 = chip.sigma_upper_1(&mut region, "S1", &word)?;

                        s1.value().zip(word_value).assert_if_known(|(s1, word)| {
                            let expected = word.rotate_right(6)
                                ^ word.rotate_right(11)
                                ^ word.rotate_right(25);
                            u32::from(*s1) == expected
                        });

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test ch",
                    |mut region| {
                        let mut offset = 0;

                        let e_value = Value::known(0x12345678);
                        let f_value = Value::known(0x9abcdef0);
                        let g_value = Value::known(0xabcd1234);

                        let e = chip.assign_word(&mut region, "e", &mut offset, &e_value, false)?;
                        let f = chip.assign_word(&mut region, "f", &mut offset, &f_value, false)?;
                        let g = chip.assign_word(&mut region, "g", &mut offset, &g_value, false)?;

                        let offset_before = offset;
                        let ch = chip.ch(&mut region, "ch", &mut offset, &e, &f, &g)?;

                        assert_eq!(offset - offset_before, CompressChip::ch_maj_rows());

                        let ch_expected = e_value
                            .zip(f_value)
                            .zip(g_value)
                            .map(|((e, f), g)| (e & f) ^ (!e & g));

                        ch.value()
                            .zip(ch_expected)
                            .assert_if_known(|(ch, expected)| u32::from(*ch) == *expected);

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test maj",
                    |mut region| {
                        let mut offset = 0;

                        let a_value = Value::known(0x12345678);
                        let b_value = Value::known(0x9abcdef0);
                        let c_value = Value::known(0xabcd1234);

                        let a = chip.assign_word(&mut region, "a", &mut offset, &a_value, false)?;
                        let b = chip.assign_word(&mut region, "b", &mut offset, &b_value, false)?;
                        let c = chip.assign_word(&mut region, "c", &mut offset, &c_value, false)?;

                        let offset_before = offset;
                        let maj = chip.maj(&mut region, "maj", &mut offset, &a, &b, &c)?;

                        assert_eq!(offset - offset_before, CompressChip::ch_maj_rows());

                        let maj_expected = a_value
                            .zip(b_value)
                            .zip(c_value)
                            .map(|((a, b), c)| (a & b) ^ (a & c) ^ (b & c));

                        maj.value()
                            .zip(maj_expected)
                            .assert_if_known(|(maj, expected)| u32::from(*maj) == *expected);

                        Ok(())
                    },
                )?;

                // Test compression.
                let digest = chip.hash_unassigned(layouter, &self.blocks)?;
                let digest_expected = values::hash_blocks_padded(&self.blocks);
                for (word, expected) in digest.iter().zip(digest_expected) {
                    word.value_u32()
                        .zip(expected)
                        .assert_if_known(|(word, expected)| word == expected);
                }

                Ok(())
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                let word_rows = CompressChip::word_rows();
                let sum_rows = CompressChip::sum_rows();
                let ch_maj_rows = CompressChip::ch_maj_rows();
                let hash_rows = CompressChip::hash_rows(NUM_BLOCKS);
                10 * word_rows + 1 + 2 * sum_rows + 2 * ch_maj_rows + hash_rows
            }
        }

        let unpadded_preimage_word_len = NUM_BLOCKS * BLOCK_WORDS - PAD_WORDS;

        let padded_preimage_words: Vec<Value<u32>> = (0..unpadded_preimage_word_len as u32)
            .chain(get_padding(unpadded_preimage_word_len))
            .map(Value::known)
            .collect();

        let blocks: [[Value<u32>; BLOCK_WORDS]; NUM_BLOCKS] = padded_preimage_words
            .chunks(BLOCK_WORDS)
            .map(|block_words| block_words.try_into().unwrap())
            .collect::<Vec<[Value<u32>; BLOCK_WORDS]>>()
            .try_into()
            .unwrap();

        let circ = MyCircuit { blocks };

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
