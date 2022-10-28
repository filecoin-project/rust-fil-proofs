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
    BLOCK_SIZE as BLOCK_WORDS,
};

use crate::{
    boolean::{AssignedBit, Bit},
    convert_assigned_f,
    sha256::{
        table16::{ROUNDS as NUM_ROUNDS, ROUND_CONSTANTS},
        FIELD_WORD_LEN as FIELD_WORDS,
    },
    AdviceIter, ColumnCount, NumCols,
};

// The number of words in the last preimage block used for padding.
pub const PAD_WORDS: usize = 3;

// The maximum number of words that can be utilized in the last block of a sha256 preimage.
pub const BLOCK_WORDS_UNPADDED: usize = BLOCK_WORDS - PAD_WORDS;

// Padded block length measured in field elements.
const BLOCK_FIELD_ELEMS: usize = BLOCK_WORDS / FIELD_WORDS;

// Each `u32` word is 4 bytes.
pub const WORD_BYTES: usize = 4;

// Number of public inputs per input state word; 32 bits and 1 packed `u32`.
pub const WORD_PUB_INPUTS: usize = 33;

// Number of public inputs for all input state words.
pub const STATE_PUB_INPUTS: usize = STATE_WORDS * WORD_PUB_INPUTS;

// Maximum number of inputs to `CompressChip::modular_sum()`.
const MODULAR_SUM_OPERANDS: usize = 5;

// AND-mask to strip two bits from last digest word.
const STRIP_MASK: u32 = 0b11111111_11111111_11111111_00111111;

// Unassigned `u32`.
#[derive(Debug, Clone, Copy)]
pub struct U32(u32);

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
    bits: [Option<AssignedBit<F>>; 32],
    // Not all assigned words will need to be packed into an `u32`.
    int: Option<AssignedU32<F>>,
    // The offset of the first row of this word in the sha256 compression region.
    offset: usize,
}

impl<F: FieldExt> Word<F> {
    pub fn bits(&self) -> [&AssignedBit<F>; 32] {
        // Any `Word` outside of this modulue should contain 32 bits.
        assert!(self.bits.iter().all(|bit| bit.is_some()));
        self.bits
            .iter()
            .map(|bit| bit.as_ref().unwrap())
            .collect::<Vec<&AssignedBit<F>>>()
            .try_into()
            .unwrap()
    }

    pub fn int(&self) -> &Option<AssignedU32<F>> {
        &self.int
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

#[derive(Clone, Debug)]
pub struct CompressConfig<F: FieldExt, const BIT_COLS: usize> {
    int_col: Column<Advice>,
    bit_cols: Vec<Column<Advice>>,
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
                .map(|(offset, col)| meta.query_advice(col, Rotation(offset.try_into().unwrap())))
                .collect()
        };

        let pack_bits = |bits: &Vec<Expression<F>>| -> Expression<F> {
            bits.iter()
                .cloned()
                .enumerate()
                .fold(Expression::Constant(F::zero()), |acc, (i, bit)| {
                    acc + Expression::Constant(F::from(1 << i)) * bit
                })
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
            let packed = pack_bits(&bits);
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
            let sigma_packed = pack_bits(&sigma_bits);
            let sigma = meta.query_advice(sigma_col, Rotation(s0_offset.try_into().unwrap()));

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
            let sigma_packed = pack_bits(&sigma_bits);
            let sigma = meta.query_advice(sigma_col, Rotation(s1_offset.try_into().unwrap()));

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
            let sigma_packed = pack_bits(&sigma_bits);
            let sigma = meta.query_advice(sigma_col, Rotation(s0_offset.try_into().unwrap()));

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
            let sigma_packed = pack_bits(&sigma_bits);
            let sigma = meta.query_advice(sigma_col, Rotation(s1_offset.try_into().unwrap()));

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
            let ch_row = pack_bits(&ch_bits);

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
            let maj_row = pack_bits(&maj_bits);

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
                        || format!("{} bits[{}]", annotation, i),
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
                || format!("{} u32", annotation),
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

    fn assign_word_pi(
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
                        || format!("{} bits[{}] from pi", annotation, i),
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
                || format!("{} u32 from pi", annotation),
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

    fn assign_input_state_pi(
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
                self.assign_word_pi(
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
            .map(|(i, word)| {
                let bits = AdviceIter::new(*offset, self.config.bit_cols.clone())
                    .take(32)
                    .enumerate()
                    .map(|(bit_index, (offset, col))| {
                        region
                            .assign_advice_from_constant(
                                || format!("iv[{}] bits[{}]", i, bit_index),
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
                        || format!("iv[{}] u32", i),
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
                            || format!("{} sum bits[{}]", annotation, i),
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
            .bits
            .chunks(bits_per_row)
            .zip(f.bits.chunks(bits_per_row))
            .zip(g.bits.chunks(bits_per_row))
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
                let e_bit = e_bit.as_ref().unwrap().copy_advice(
                    || format!("{} copy e_bits[{}]", annotation, bit_index),
                    region,
                    *e_col,
                    *offset,
                )?;
                let f_bit = f_bit.as_ref().unwrap().copy_advice(
                    || format!("{} copy f_bits[{}]", annotation, bit_index),
                    region,
                    *f_col,
                    *offset,
                )?;
                let g_bit = g_bit.as_ref().unwrap().copy_advice(
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
            .bits
            .chunks(bits_per_row)
            .zip(b.bits.chunks(bits_per_row))
            .zip(c.bits.chunks(bits_per_row))
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
                let a_bit = a_bit.as_ref().unwrap().copy_advice(
                    || format!("{} copy a_bits[{}]", annotation, bit_index),
                    region,
                    *a_col,
                    *offset,
                )?;
                let b_bit = b_bit.as_ref().unwrap().copy_advice(
                    || format!("{} copy b_bits[{}]", annotation, bit_index),
                    region,
                    *b_col,
                    *offset,
                )?;
                let c_bit = c_bit.as_ref().unwrap().copy_advice(
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

    pub fn compress_unassigned_state(
        &self,
        mut layouter: impl Layouter<F>,
        block: &[Value<u32>; BLOCK_WORDS],
        state: &[Value<u32>; STATE_WORDS],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        layouter.assign_region(
            || "sha256 compress",
            |mut region| {
                let mut offset = 0;
                let state_in = self.assign_input_state(&mut region, &mut offset, state)?;
                self.compress_inner(&mut region, "compress", &mut offset, block, &state_in, true)
            },
        )
    }

    pub fn compress_assigned_state(
        &self,
        mut layouter: impl Layouter<F>,
        block: &[Value<u32>; BLOCK_WORDS],
        state: &[Word<F>; STATE_WORDS],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        layouter.assign_region(
            || "sha256 compress",
            |mut region| {
                let mut offset = 0;

                // Copy each assigned input state word and assign each's bits.
                let state_in: [Word<F>; 8] = state
                    .iter()
                    .enumerate()
                    .map(|(i, word)| {
                        let word = word.int.as_ref().expect("unassigned input state `u32`");

                        self.config.s_check_word_bits.enable(&mut region, offset)?;
                        self.config.s_pack_word_bits.enable(&mut region, offset)?;

                        let bits = AdviceIter::new(offset, self.config.bit_cols.clone())
                            .take(32)
                            .enumerate()
                            .map(|(bit_index, (offset, col))| {
                                region
                                    .assign_advice(
                                        || format!("state_in[{}] bits[{}]", i, bit_index),
                                        col,
                                        offset,
                                        || {
                                            word.value().map(|word| {
                                                Bit(u32::from(word) >> bit_index & 1 == 1)
                                            })
                                        },
                                    )
                                    .map(Some)
                            })
                            .collect::<Result<Vec<Option<AssignedBit<F>>>, Error>>()?;

                        let int = word.copy_advice(
                            || format!("copy state_in[{}] u32", i),
                            &mut region,
                            self.config.int_col,
                            offset,
                        )?;

                        let word = Word {
                            bits: bits.try_into().unwrap(),
                            int: Some(int),
                            offset,
                        };
                        offset += Self::word_rows();
                        Ok(word)
                    })
                    .collect::<Result<Vec<Word<F>>, Error>>()?
                    .try_into()
                    .unwrap();

                self.compress_inner(&mut region, "compress", &mut offset, block, &state_in, true)
            },
        )
    }

    pub fn compress_pi_state(
        &self,
        mut layouter: impl Layouter<F>,
        block: &[Value<u32>; BLOCK_WORDS],
        pi_col: Column<Instance>,
        pi_rows: Range<usize>,
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        layouter.assign_region(
            || "sha256 compress",
            |mut region| {
                let mut offset = 0;
                let state_in =
                    self.assign_input_state_pi(&mut region, &mut offset, pi_col, pi_rows.clone())?;
                self.compress_inner(&mut region, "compress", &mut offset, block, &state_in, true)
            },
        )
    }

    fn compress_inner(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        offset: &mut usize,
        block: &[Value<u32>; BLOCK_WORDS],
        state: &[Word<F>; STATE_WORDS],
        is_last_block: bool,
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        assert!(
            state
                .iter()
                .all(|word| word.bits.iter().all(|bit| bit.is_some())),
            "input state's 32 bits must be assigned",
        );
        assert!(
            state.iter().all(|word| word.int.is_some()),
            "input state's word u32 must be assigned",
        );

        let mut w = Vec::<Word<F>>::with_capacity(NUM_ROUNDS);

        // Assign the first words of the message schedule to the input block.
        for (i, word) in block.iter().enumerate() {
            let word = self.assign_word(
                region,
                &format!("{} block words_{}", annotation, i),
                offset,
                word,
                true,
            )?;
            w.push(word);
        }

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

        let [a_in, b_in, c_in, d_in, e_in, f_in, g_in, h_in] = state.clone();
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state.clone();

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

    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        blocks: &[[Value<u32>; BLOCK_WORDS]],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        layouter.assign_region(
            || "sha256",
            |mut region| self.hash_in_region(&mut region, &mut 0, blocks),
        )
    }

    pub fn hash_in_region(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        blocks: &[[Value<u32>; BLOCK_WORDS]],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        assert!(!blocks.is_empty());
        let last_block = blocks.len() - 1;

        let mut state = self.assign_iv(region, offset)?;
        for (i, block) in blocks.iter().enumerate() {
            let is_last_block = i == last_block;
            state = self.compress_inner(
                region,
                &format!("compress block_{}", i),
                offset,
                block,
                &state,
                is_last_block,
            )?;
        }

        Ok(state)
    }

    #[inline]
    const fn distinct_sigma_col() -> bool {
        Self::word_rows() < 3
    }

    #[inline]
    const fn word_rows() -> usize {
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

#[derive(Clone, Debug)]
pub struct CompressFieldConfig<F: FieldExt, const BIT_COLS: usize> {
    compress: CompressConfig<F, BIT_COLS>,
    unstripped_col: Column<Advice>,
    stripped_col: Column<Advice>,
    stripped_offset: usize,
    s_strip: Selector,
}

#[derive(Clone, Debug)]
pub struct CompressFieldChip<F: FieldExt, const BIT_COLS: usize> {
    config: CompressFieldConfig<F, BIT_COLS>,
}

impl<F: FieldExt, const BIT_COLS: usize> Chip<F> for CompressFieldChip<F, BIT_COLS> {
    type Config = CompressFieldConfig<F, BIT_COLS>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const BIT_COLS: usize> ColumnCount for CompressFieldChip<F, BIT_COLS> {
    #[inline]
    fn num_cols() -> NumCols {
        CompressChip::<F, BIT_COLS>::num_cols()
    }
}

impl<F: FieldExt, const BIT_COLS: usize> CompressFieldChip<F, BIT_COLS> {
    pub fn construct(config: CompressFieldConfig<F, BIT_COLS>) -> Self {
        CompressFieldChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: &[Column<Advice>],
        fixed: &Column<Fixed>,
    ) -> CompressFieldConfig<F, BIT_COLS> {
        let compress = CompressChip::configure(meta, advice, fixed);

        // Columns for a `u32` and `u32` after its two most significant bits have been stripped from
        // it's first byte.
        let unstripped_col = compress.int_col;
        let stripped_col = compress.sigma_col;

        // If the unstripped and stripped `u32`s share the same column, the stripped value will be
        // placed in the row below the unstripped `u32`; otherwise use a single row.
        let stripped_offset = (unstripped_col == stripped_col) as i32;

        let s_strip = meta.selector();
        meta.create_gate("strip_bits", |meta| {
            let s = meta.query_selector(s_strip);

            // Unstripped and stripped `u32`s.
            let unstripped = meta.query_advice(unstripped_col, Rotation::cur());
            let stripped = meta.query_advice(stripped_col, Rotation(stripped_offset));

            // Unstripped `u32`'s bits.
            let mut bits: Vec<Expression<F>> = AdviceIter::from(compress.bit_cols.clone())
                .take(32)
                .map(|(offset, col)| meta.query_advice(col, Rotation(offset.try_into().unwrap())))
                .collect();

            let unstripped_packed = bits
                .iter()
                .cloned()
                .enumerate()
                .fold(Expression::Constant(F::zero()), |acc, (i, bit)| {
                    acc + Expression::Constant(F::from(1 << i)) * bit
                });

            let stripped_packed = bits.drain(..).enumerate().fold(
                Expression::Constant(F::zero()),
                |acc, (i, bit)| {
                    if i == 6 || i == 7 {
                        acc
                    } else {
                        acc + Expression::Constant(F::from(1 << i)) * bit
                    }
                },
            );

            Constraints::with_selector(
                s,
                [
                    ("unstripped packing", unstripped - unstripped_packed),
                    ("stripped packing", stripped - stripped_packed),
                ],
            )
        });

        CompressFieldConfig {
            compress,
            unstripped_col,
            stripped_col,
            stripped_offset: stripped_offset.try_into().unwrap(),
            s_strip,
        }
    }

    fn strip(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        word: &AssignedU32<F>,
    ) -> Result<AssignedU32<F>, Error> {
        self.config.s_strip.enable(region, *offset)?;

        // Copy last digest word into new row.
        let word = word.copy_advice(
            || "copy last digest word",
            region,
            self.config.unstripped_col,
            *offset,
        )?;
        let word_value = word.value().map(u32::from);

        // Assign last digest word's bits.
        AdviceIter::new(*offset, self.config.compress.bit_cols.clone())
            .take(32)
            .enumerate()
            .map(|(i, (offset, col))| {
                region.assign_advice(
                    || format!("last digest word bits[{}]", i),
                    col,
                    offset,
                    || word_value.map(|word| Bit(word >> i & 1 == 1)),
                )
            })
            .collect::<Result<Vec<AssignedBit<F>>, Error>>()?;

        // Assigned last digest word after its two most significant bits of its first byte have been
        // stripped.
        let stripped = region.assign_advice(
            || "stripped",
            self.config.stripped_col,
            *offset + self.config.stripped_offset,
            || word_value.map(|word| U32(word & STRIP_MASK)),
        )?;

        *offset += Self::strip_rows();

        Ok(stripped)
    }

    pub fn hash_field_elems_unassigned(
        &self,
        mut layouter: impl Layouter<F>,
        preimage: &[Value<F>],
    ) -> Result<[AssignedU32<F>; STATE_WORDS], Error> {
        let preimage_elems = preimage.len();
        assert_eq!(preimage_elems % BLOCK_FIELD_ELEMS, 0);

        let preimage_blocks: Vec<[Value<u32>; BLOCK_WORDS]> = preimage
            .chunks(BLOCK_FIELD_ELEMS)
            .map(|block_elems| {
                block_elems
                    .iter()
                    .flat_map(field_to_sha256_words_values)
                    .collect::<Vec<Value<u32>>>()
                    .try_into()
                    .unwrap()
            })
            .collect();

        let compress_chip = CompressChip::construct(self.config.compress.clone());

        layouter.assign_region(
            || "sha256",
            |mut region| {
                let mut offset = 0;

                let mut digest: [AssignedU32<F>; STATE_WORDS] = compress_chip
                    .hash_in_region(&mut region, &mut offset, &preimage_blocks)?
                    .iter()
                    .map(|word| word.int.clone().unwrap())
                    .collect::<Vec<AssignedU32<F>>>()
                    .try_into()
                    .unwrap();

                digest[STATE_WORDS - 1] =
                    self.strip(&mut region, &mut offset, &digest[STATE_WORDS - 1])?;

                Ok(digest)
            },
        )
    }

    #[inline]
    fn strip_rows() -> usize {
        CompressChip::<F, BIT_COLS>::word_rows()
    }
}

fn field_to_sha256_words<F: FieldExt>(f: &F) -> [u32; FIELD_WORDS] {
    let mut words = [0; FIELD_WORDS];
    for (word, word_bytes) in words
        .iter_mut()
        .zip(f.to_repr().as_ref().chunks(WORD_BYTES))
    {
        // Field elements are little-endian; words are big-endian.
        *word = u32::from_be_bytes(word_bytes.try_into().unwrap());
    }
    words
}

#[allow(dead_code)]
fn sha256_words_to_field<F: FieldExt>(words: &[u32]) -> F {
    assert_eq!(words.len(), FIELD_WORDS);
    let repr_bytes: Vec<u8> = words
        .iter()
        .copied()
        // Most-significant word byte comes first in field element.
        .flat_map(u32::to_be_bytes)
        .collect();
    let mut repr = F::Repr::default();
    repr.as_mut().copy_from_slice(&repr_bytes);
    F::from_repr_vartime(repr).expect("words are invalid field element")
}

fn field_to_sha256_words_values<F: FieldExt>(value: &Value<F>) -> [Value<u32>; FIELD_WORDS] {
    value.map(|f| field_to_sha256_words(&f)).transpose_array()
}

pub fn sha256_word_values_padded(preimage: &[Value<u32>]) -> [Value<u32>; STATE_WORDS] {
    let padded_preimage_word_len = preimage.len();
    assert!(padded_preimage_word_len >= PAD_WORDS);

    let unpadded_preimage_word_len = preimage
        .iter()
        .rposition(|word| {
            let mut first_pad_word = false;
            word.map(|word| first_pad_word = word == 1u32 << 31);
            first_pad_word
        })
        .expect("preimage does not contain first padding word");

    let mut unpadded_preimage_bytes =
        Vec::<u8>::with_capacity(unpadded_preimage_word_len * WORD_BYTES);
    for word in &preimage[..unpadded_preimage_word_len] {
        word.map(|word| unpadded_preimage_bytes.extend_from_slice(&word.to_be_bytes()));
    }

    Sha256::digest(&unpadded_preimage_bytes)
        .chunks(WORD_BYTES)
        .map(|word_bytes| Value::known(u32::from_be_bytes(word_bytes.try_into().unwrap())))
        .collect::<Vec<Value<u32>>>()
        .try_into()
        .unwrap()
}

pub fn sha256_block_values_padded(
    blocks: &[[Value<u32>; BLOCK_WORDS]],
) -> [Value<u32>; STATE_WORDS] {
    let preimage_words: Vec<Value<u32>> = blocks.iter().cloned().flatten().collect();
    sha256_word_values_padded(&preimage_words)
}

pub fn sha256_field_values_padded<F: FieldExt>(preimage: &[Value<F>]) -> [Value<u32>; STATE_WORDS] {
    let mut preimage_words = Vec::<Value<u32>>::with_capacity(preimage.len() * FIELD_WORDS);
    for f in preimage {
        preimage_words.extend_from_slice(&field_to_sha256_words_values(f));
    }
    sha256_word_values_padded(&preimage_words)
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};

    use crate::{sha256::get_padding, CircuitSize, ColumnBuilder};

    // Configures the number of advice columns in which to assign bits.
    const BIT_COLS: usize = 16;

    type CompressChip = super::CompressChip<Fp, BIT_COLS>;
    type CompressConfig = super::CompressConfig<Fp, BIT_COLS>;

    #[test]
    #[ignore]
    fn test_compress_chip_assign_word() {
        #[derive(Clone)]
        struct MyCircuit {
            a: Value<u32>,
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    a: Value::unknown(),
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

                layouter.assign_region(
                    || "region",
                    |mut region| {
                        let mut offset = 0;

                        let offset_before = offset;
                        let word_1 =
                            chip.assign_word(&mut region, "word_1", &mut offset, &self.a, false)?;
                        assert_eq!(word_1.offset, offset_before);
                        assert_eq!(offset - offset_before, CompressChip::word_rows());
                        assert!(
                            word_1.bits.iter().all(|bit| bit.is_some()) && word_1.int.is_none()
                        );

                        let offset_before = offset;
                        let word_2 =
                            chip.assign_word(&mut region, "word_2", &mut offset, &self.a, true)?;
                        assert_eq!(word_2.offset, offset_before);
                        assert_eq!(offset - offset_before, CompressChip::word_rows());
                        assert!(
                            word_2.bits.iter().all(|bit| bit.is_some()) && word_2.int.is_some()
                        );

                        self.a
                            .zip(word_1.value_u32())
                            .zip(word_2.value_u32())
                            .assert_if_known(|((a, word_1), word_2)| a == word_1 && a == word_2);

                        for (bit_1, bit_2) in word_1.bits.iter().zip(word_2.bits.iter()) {
                            bit_1
                                .as_ref()
                                .unwrap()
                                .value()
                                .map(bool::from)
                                .zip(bit_2.as_ref().unwrap().value().map(bool::from))
                                .assert_if_known(|(bit_1, bit_2)| bit_1 == bit_2);
                        }

                        Ok(())
                    },
                )
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                2 * CompressChip::word_rows()
            }
        }

        let circ = MyCircuit {
            a: Value::known(0xafbc10ff),
        };

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    #[ignore]
    fn test_compress_chip_modular_sum() {
        const CONSTANT: u32 = 0xffff0000;

        #[derive(Clone)]
        struct MyCircuit {
            a: Value<u32>,
            b: Value<u32>,
            c: Value<u32>,
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    a: Value::unknown(),
                    b: Value::unknown(),
                    c: Value::unknown(),
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
                let operand_cols = config.sum_operand_cols.clone();

                let chip = CompressChip::construct(config);

                let sum_rows = CompressChip::sum_rows();
                let sum_with_decomp_rows = sum_rows + CompressChip::word_rows();

                layouter.assign_region(
                    || "region",
                    |mut region| {
                        let mut offset = 0;

                        let a = region.assign_advice(
                            || "a",
                            operand_cols[0],
                            offset,
                            || self.a.map(U32),
                        )?;
                        let b = region.assign_advice(
                            || "b",
                            operand_cols[1],
                            offset,
                            || self.b.map(U32),
                        )?;
                        let c = region.assign_advice(
                            || "c",
                            operand_cols[2],
                            offset,
                            || self.c.map(U32),
                        )?;
                        offset += 1;

                        // Test `modular_sum` without constant.
                        let operands = [&a, &b, &c];
                        let sum_expected = self.a + self.b + self.c;

                        // Test without binary decomposition.
                        let offset_before = offset;
                        let sum = chip.modular_sum(
                            &mut region,
                            "sum_1",
                            &mut offset,
                            &operands,
                            None,
                            false,
                        )?;
                        assert_eq!(offset - offset_before, sum_rows);
                        assert_eq!(sum.offset, offset_before);
                        assert!(sum.bits.iter().all(|bit| bit.is_none()) && sum.int.is_some());
                        sum.value_u32()
                            .zip(sum_expected)
                            .assert_if_known(|(sum, expected)| sum == expected);

                        // Test with binary decomposition.
                        let offset_before = offset;
                        let sum = chip.modular_sum(
                            &mut region,
                            "sum_2",
                            &mut offset,
                            &operands,
                            None,
                            true,
                        )?;
                        assert_eq!(offset - offset_before, sum_with_decomp_rows);
                        assert_eq!(sum.offset, offset_before + sum_rows);
                        assert!(sum.bits.iter().all(|bit| bit.is_some()) && sum.int.is_some());
                        sum.bits
                            .iter()
                            .enumerate()
                            .fold(Value::known(0u32), |acc, (i, bit)| {
                                acc + bit
                                    .as_ref()
                                    .unwrap()
                                    .value()
                                    .map(|bit| (bool::from(bit) as u32) << i)
                            })
                            .zip(sum.value_u32())
                            .zip(sum_expected)
                            .assert_if_known(|((sum_bits, sum_u32), expected)| {
                                sum_bits == expected && sum_u32 == expected
                            });

                        // Test `modular_sum` with constant.
                        let sum_expected = sum_expected + Value::known(CONSTANT);

                        // Test without binary decomposition.
                        let offset_before = offset;
                        let sum = chip.modular_sum(
                            &mut region,
                            "sum_3",
                            &mut offset,
                            &operands,
                            Some(CONSTANT),
                            false,
                        )?;
                        assert_eq!(offset - offset_before, sum_rows);
                        assert_eq!(sum.offset, offset_before);
                        assert!(sum.bits.iter().all(|bit| bit.is_none()) && sum.int.is_some());
                        sum.value_u32()
                            .zip(sum_expected)
                            .assert_if_known(|(sum, expected)| sum == expected);

                        // Test with binary decomposition.
                        let offset_before = offset;
                        let sum = chip.modular_sum(
                            &mut region,
                            "sum_4",
                            &mut offset,
                            &operands,
                            Some(CONSTANT),
                            true,
                        )?;
                        assert_eq!(offset - offset_before, sum_with_decomp_rows);
                        assert_eq!(sum.offset, offset_before + sum_rows);
                        assert!(sum.bits.iter().all(|bit| bit.is_some()) && sum.int.is_some());
                        sum.bits
                            .iter()
                            .enumerate()
                            .fold(Value::known(0u32), |acc, (i, bit)| {
                                acc + bit
                                    .as_ref()
                                    .unwrap()
                                    .value()
                                    .map(|bit| (bool::from(bit) as u32) << i)
                            })
                            .zip(sum.value_u32())
                            .zip(sum_expected)
                            .assert_if_known(|((sum_bits, sum_u32), expected)| {
                                sum_bits == expected && sum_u32 == expected
                            });

                        Ok(())
                    },
                )
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                4 * CompressChip::sum_rows() + 2 * CompressChip::word_rows() + 1
            }
        }

        let circ = MyCircuit {
            a: Value::known(0xff00ff00),
            b: Value::known(0x00ff00ff),
            c: Value::known(0xabcdef00),
        };

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    #[ignore]
    fn test_compress_chip_sigma() {
        #[derive(Clone)]
        struct MyCircuit {
            word: Value<u32>,
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    word: Value::unknown(),
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

                // Test lower sigmas.
                layouter.assign_region(
                    || "sigma_lower",
                    |mut region| {
                        let mut offset = 0;

                        let word =
                            chip.assign_word(&mut region, "word", &mut offset, &self.word, true)?;

                        let s0 = chip.sigma_lower_0(&mut region, "s0", &word)?;
                        let s1 = chip.sigma_lower_1(&mut region, "s1", &word)?;

                        self.word
                            .zip(s0.value().map(u32::from))
                            .assert_if_known(|(word, s0)| {
                                *s0 == word.rotate_right(7) ^ word.rotate_right(18) ^ (word >> 3)
                            });

                        self.word
                            .zip(s1.value().map(u32::from))
                            .assert_if_known(|(word, s1)| {
                                *s1 == word.rotate_right(17) ^ word.rotate_right(19) ^ (word >> 10)
                            });

                        Ok(())
                    },
                )?;

                // Test upper sigmas; use second region so upper sigmas are not assinged to the same
                // cells as the lower sigmas.
                layouter.assign_region(
                    || "sigma_upper",
                    |mut region| {
                        let mut offset = 0;

                        let word =
                            chip.assign_word(&mut region, "word", &mut offset, &self.word, true)?;

                        let s0 = chip.sigma_upper_0(&mut region, "S0", &word)?;
                        let s1 = chip.sigma_upper_1(&mut region, "S1", &word)?;

                        self.word
                            .zip(s0.value().map(u32::from))
                            .assert_if_known(|(word, s0)| {
                                *s0 == word.rotate_right(2)
                                    ^ word.rotate_right(13)
                                    ^ word.rotate_right(22)
                            });

                        self.word
                            .zip(s1.value().map(u32::from))
                            .assert_if_known(|(word, s1)| {
                                *s1 == word.rotate_right(6)
                                    ^ word.rotate_right(11)
                                    ^ word.rotate_right(25)
                            });

                        Ok(())
                    },
                )
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                CompressChip::word_rows()
            }
        }

        let circ = MyCircuit {
            word: Value::known(0xfa01ff50),
        };

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    #[ignore]
    fn test_compress_chip_ch_maj() {
        #[derive(Clone)]
        struct MyCircuit {
            word_1: Value<u32>,
            word_2: Value<u32>,
            word_3: Value<u32>,
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    word_1: Value::unknown(),
                    word_2: Value::unknown(),
                    word_3: Value::unknown(),
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

                // Test `ch`.
                layouter.assign_region(
                    || "ch",
                    |mut region| {
                        let mut offset = 0;

                        let word_1 = chip.assign_word(
                            &mut region,
                            "word_1",
                            &mut offset,
                            &self.word_1,
                            false,
                        )?;
                        let word_2 = chip.assign_word(
                            &mut region,
                            "word_2",
                            &mut offset,
                            &self.word_2,
                            false,
                        )?;
                        let word_3 = chip.assign_word(
                            &mut region,
                            "word_3",
                            &mut offset,
                            &self.word_3,
                            false,
                        )?;

                        let offset_before = offset;
                        let ch =
                            chip.ch(&mut region, "ch", &mut offset, &word_1, &word_2, &word_3)?;

                        assert_eq!(offset - offset_before, CompressChip::ch_maj_rows());
                        self.word_1
                            .zip(self.word_2)
                            .zip(self.word_3)
                            .zip(ch.value().map(u32::from))
                            .assert_if_known(|(((e, f), g), ch)| *ch == (e & f) ^ (!e & g));

                        Ok(())
                    },
                )?;

                // Test `maj`.
                layouter.assign_region(
                    || "maj",
                    |mut region| {
                        let mut offset = 0;

                        let word_1 = chip.assign_word(
                            &mut region,
                            "word_1",
                            &mut offset,
                            &self.word_1,
                            false,
                        )?;
                        let word_2 = chip.assign_word(
                            &mut region,
                            "word_2",
                            &mut offset,
                            &self.word_2,
                            false,
                        )?;
                        let word_3 = chip.assign_word(
                            &mut region,
                            "word_3",
                            &mut offset,
                            &self.word_3,
                            false,
                        )?;

                        let offset_before = offset;
                        let maj =
                            chip.maj(&mut region, "maj", &mut offset, &word_1, &word_2, &word_3)?;

                        assert_eq!(offset - offset_before, CompressChip::ch_maj_rows());
                        self.word_1
                            .zip(self.word_2)
                            .zip(self.word_3)
                            .zip(maj.value().map(u32::from))
                            .assert_if_known(|(((a, b), c), maj)| {
                                *maj == (a & b) ^ (a & c) ^ (b & c)
                            });

                        Ok(())
                    },
                )
            }
        }

        let circ = MyCircuit {
            word_1: Value::known(0x12345678),
            word_2: Value::known(0x9abcdef0),
            word_3: Value::known(0xabcd1234),
        };

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                6 * CompressChip::word_rows() + 2 * CompressChip::ch_maj_rows()
            }
        }

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_compress_chip() {
        #[derive(Clone)]
        struct MyCircuit {
            block: [Value<u32>; BLOCK_WORDS],
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    block: [Value::unknown(); BLOCK_WORDS],
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
                layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let state_in = IV
                    .iter()
                    .copied()
                    .map(Value::known)
                    .collect::<Vec<Value<u32>>>()
                    .try_into()
                    .unwrap();

                let digest = CompressChip::construct(config).compress_unassigned_state(
                    layouter,
                    &self.block,
                    &state_in,
                )?;

                let digest_expected = sha256_word_values_padded(&self.block);

                for (word, word_expected) in digest.iter().zip(digest_expected) {
                    word.value_u32()
                        .zip(word_expected)
                        .assert_if_known(|(word, word_expected)| word == word_expected);
                }

                Ok(())
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                CompressChip::hash_rows(1)
            }
        }

        let block: [u32; BLOCK_WORDS] = (0..BLOCK_WORDS_UNPADDED as u32)
            .chain(get_padding(BLOCK_WORDS_UNPADDED))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        let circ = MyCircuit {
            block: Value::known(block).transpose_array(),
        };

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_compress_chip_pi_state() {
        #[derive(Clone)]
        struct MyConfig {
            compress: CompressConfig,
            pi: Column<Instance>,
        }

        #[derive(Clone)]
        struct MyCircuit {
            block: [Value<u32>; BLOCK_WORDS],
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = MyConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    block: [Value::unknown(); BLOCK_WORDS],
                }
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let (advice, _, fixed, _) = ColumnBuilder::new()
                    .with_chip::<CompressChip>()
                    .create_columns(meta);

                let pi = meta.instance_column();
                meta.enable_equality(pi);

                let compress = CompressChip::configure(meta, &advice, &fixed[0]);

                MyConfig { compress, pi }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let MyConfig {
                    compress: compress_config,
                    pi: pi_col,
                } = config;

                let pi_rows = 0..STATE_PUB_INPUTS;

                let digest = CompressChip::construct(compress_config).compress_pi_state(
                    layouter,
                    &self.block,
                    pi_col,
                    pi_rows,
                )?;

                let digest_expected = sha256_word_values_padded(&self.block);

                for (word, word_expected) in digest.iter().zip(digest_expected) {
                    word.value_u32()
                        .zip(word_expected)
                        .assert_if_known(|(word, word_expected)| word == word_expected);
                }

                Ok(())
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                CompressChip::hash_rows(1)
            }
        }

        let block: [u32; BLOCK_WORDS] = (0..BLOCK_WORDS_UNPADDED as u32)
            .chain(get_padding(BLOCK_WORDS_UNPADDED))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        let circ = MyCircuit {
            block: Value::known(block).transpose_array(),
        };

        let mut pub_inputs = Vec::<Fp>::with_capacity(STATE_PUB_INPUTS);
        for word in &IV {
            for i in 0..32 {
                let bit = word >> i & 1 == 1;
                pub_inputs.push(Fp::from(bit as u64));
            }
            pub_inputs.push(Fp::from(*word as u64));
        }

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![pub_inputs]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_compress_chip_hash() {
        // Configures the number blocks in the padded preimage.
        const NUM_BLOCKS: usize = 2;

        #[derive(Clone)]
        struct MyCircuit {
            blocks: [[Value<u32>; BLOCK_WORDS]; NUM_BLOCKS],
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    blocks: [[Value::unknown(); BLOCK_WORDS]; NUM_BLOCKS],
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
                layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let digest = CompressChip::construct(config).hash(layouter, &self.blocks)?;

                let digest_expected = sha256_block_values_padded(&self.blocks);

                for (word, word_expected) in digest.iter().zip(digest_expected) {
                    word.value_u32()
                        .zip(word_expected)
                        .assert_if_known(|(word, word_expected)| word == word_expected);
                }

                Ok(())
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                CompressChip::hash_rows(NUM_BLOCKS)
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

    #[test]
    fn test_compress_field_chip_hash() {
        // Configures the number of blocks in the padded preimage.
        const NUM_BLOCKS: usize = 2;

        // The number of field elements in the padded preimage.
        const PREIMAGE_FIELD_ELEMS: usize = NUM_BLOCKS * BLOCK_FIELD_ELEMS;

        // Padding's field element length.
        const PAD_FIELD_ELEMS: usize = 1;

        type CompressFieldChip = super::CompressFieldChip<Fp, BIT_COLS>;
        type CompressFieldConfig = super::CompressFieldConfig<Fp, BIT_COLS>;

        #[derive(Clone)]
        struct MyCircuit {
            preimage: Vec<Value<Fp>>,
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressFieldConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    preimage: vec![Value::unknown(); PREIMAGE_FIELD_ELEMS],
                }
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let (advice, _, fixed, _) = ColumnBuilder::new()
                    .with_chip::<CompressFieldChip>()
                    .create_columns(meta);
                CompressFieldChip::configure(meta, &advice, &fixed[0])
            }

            fn synthesize(
                &self,
                config: Self::Config,
                layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let digest = CompressFieldChip::construct(config)
                    .hash_field_elems_unassigned(layouter, &self.preimage)?;

                let mut digest_expected = sha256_field_values_padded(&self.preimage);
                digest_expected[STATE_WORDS - 1] =
                    digest_expected[STATE_WORDS - 1].map(|word| word & STRIP_MASK);

                for (word, word_expected) in digest.iter().zip(digest_expected) {
                    word.value()
                        .zip(word_expected)
                        .assert_if_known(|(word, word_expected)| {
                            u32::from(*word) == *word_expected
                        });
                }

                Ok(())
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                CompressChip::hash_rows(NUM_BLOCKS)
            }
        }

        let unpadded_preimage_field_len = PREIMAGE_FIELD_ELEMS - PAD_FIELD_ELEMS;
        let unpadded_preimage_word_len = unpadded_preimage_field_len * FIELD_WORDS;

        let mut padded_preimage = Vec::<Value<Fp>>::with_capacity(PREIMAGE_FIELD_ELEMS);
        for i in 0..unpadded_preimage_field_len as u64 {
            padded_preimage.push(Value::known(Fp::from(i)));
        }
        for pad_words in get_padding(unpadded_preimage_word_len).chunks(FIELD_WORDS) {
            padded_preimage.push(Value::known(sha256_words_to_field(pad_words)));
        }

        let circ = MyCircuit {
            preimage: padded_preimage,
        };

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
