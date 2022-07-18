//! Gadget and chips for the [SHA-256] hash function.
//!
//! [SHA-256]: https://tools.ietf.org/html/rfc6234

use std::cmp::min;
use std::convert::TryInto;
use std::fmt;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};

use crate::{
    boolean::AssignedBits,
    uint32::{AssignedU32, StripBitsChip, StripBitsConfig},
    AdviceIter, ColumnCount, NumCols, WitnessOrCopy,
};

// Don't reformat code copied from `halo2_gadgets` repo.
#[rustfmt::skip]
mod table16;

pub use table16::{BlockWord, Table16Chip, Table16Config};

use table16::{
    CompressionConfig, MessageScheduleConfig, SpreadTableChip, SpreadTableConfig, State, IV, STATE,
};

// TODO (jake): remove
use table16::{get_d_row, get_h_row, match_state, RoundIdx, StateWord};

/// The size of a SHA-256 block, in 32-bit words.
pub const BLOCK_SIZE: usize = 16;
/// The size of a SHA-256 digest, in 32-bit words.
pub const DIGEST_SIZE: usize = 8;

// Each field element is eight 32-bit words.
const FIELD_WORD_LEN: usize = 8;

/// The set of circuit instructions required to use the [`Sha256`] gadget.
pub trait Sha256Instructions<F: FieldExt>: Chip<F> {
    /// Variable representing the SHA-256 internal state.
    type State: Clone + fmt::Debug;
    /// Variable representing a 32-bit word of the input block to the SHA-256 compression
    /// function.
    type BlockWord: Copy + fmt::Debug + Default;

    /// Places the SHA-256 IV in the circuit, returning the initial state variable.
    fn initialization_vector(&self, layouter: &mut impl Layouter<F>) -> Result<Self::State, Error>;

    /// Creates an initial state from the output state of a previous block
    fn initialization(
        &self,
        layouter: &mut impl Layouter<F>,
        init_state: &Self::State,
    ) -> Result<Self::State, Error>;

    /// Starting from the given initialized state, processes a block of input and returns the
    /// final state.
    fn compress(
        &self,
        layouter: &mut impl Layouter<F>,
        initialized_state: &Self::State,
        input: [Self::BlockWord; BLOCK_SIZE],
    ) -> Result<Self::State, Error>;

    /// Converts the given state into a message digest.
    fn digest(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::State,
    ) -> Result<[Self::BlockWord; DIGEST_SIZE], Error>;
}

/// The output of a SHA-256 circuit invocation.
#[derive(Debug)]
pub struct Sha256Digest<BlockWord>([BlockWord; DIGEST_SIZE]);

/// A gadget that constrains a SHA-256 invocation. It supports input at a granularity of
/// 32 bits.
#[derive(Debug)]
pub struct Sha256<F: FieldExt, CS: Sha256Instructions<F>> {
    chip: CS,
    state: CS::State,
    cur_block: Vec<CS::BlockWord>,
    length: usize,
}

impl<F: FieldExt, Sha256Chip: Sha256Instructions<F>> Sha256<F, Sha256Chip> {
    /// Create a new hasher instance.
    pub fn new(chip: Sha256Chip, mut layouter: impl Layouter<F>) -> Result<Self, Error> {
        let state = chip.initialization_vector(&mut layouter)?;
        Ok(Sha256 {
            chip,
            state,
            cur_block: Vec::with_capacity(BLOCK_SIZE),
            length: 0,
        })
    }

    /// Digest data, updating the internal state.
    pub fn update(
        &mut self,
        mut layouter: impl Layouter<F>,
        mut data: &[Sha256Chip::BlockWord],
    ) -> Result<(), Error> {
        self.length += data.len() * 32;

        // Fill the current block, if possible.
        let remaining = BLOCK_SIZE - self.cur_block.len();
        let (l, r) = data.split_at(min(remaining, data.len()));
        self.cur_block.extend_from_slice(l);
        data = r;

        // If we still don't have a full block, we are done.
        if self.cur_block.len() < BLOCK_SIZE {
            return Ok(());
        }

        // Process the now-full current block.
        self.state = self.chip.compress(
            &mut layouter,
            &self.state,
            self.cur_block[..]
                .try_into()
                .expect("cur_block.len() == BLOCK_SIZE"),
        )?;
        self.cur_block.clear();

        // Process any additional full blocks.
        let mut chunks_iter = data.chunks_exact(BLOCK_SIZE);
        for chunk in &mut chunks_iter {
            self.state = self.chip.initialization(&mut layouter, &self.state)?;
            self.state = self.chip.compress(
                &mut layouter,
                &self.state,
                chunk.try_into().expect("chunk.len() == BLOCK_SIZE"),
            )?;
        }

        // Cache the remaining partial block, if any.
        let rem = chunks_iter.remainder();
        self.cur_block.extend_from_slice(rem);

        Ok(())
    }

    /// Retrieve result and consume hasher instance.
    pub fn finalize(
        mut self,
        mut layouter: impl Layouter<F>,
    ) -> Result<Sha256Digest<Sha256Chip::BlockWord>, Error> {
        // Pad the remaining block
        if !self.cur_block.is_empty() {
            let padding = vec![Sha256Chip::BlockWord::default(); BLOCK_SIZE - self.cur_block.len()];
            self.cur_block.extend_from_slice(&padding);
            self.state = self.chip.initialization(&mut layouter, &self.state)?;
            self.state = self.chip.compress(
                &mut layouter,
                &self.state,
                self.cur_block[..]
                    .try_into()
                    .expect("cur_block.len() == BLOCK_SIZE"),
            )?;
        }
        self.chip
            .digest(&mut layouter, &self.state)
            .map(Sha256Digest)
    }

    /// Convenience function to compute hash of the data. It will handle hasher creation,
    /// data feeding and finalization.
    pub fn digest(
        chip: Sha256Chip,
        mut layouter: impl Layouter<F>,
        data: &[Sha256Chip::BlockWord],
    ) -> Result<Sha256Digest<Sha256Chip::BlockWord>, Error> {
        let mut hasher = Self::new(chip, layouter.namespace(|| "init"))?;
        hasher.update(layouter.namespace(|| "update"), data)?;
        hasher.finalize(layouter.namespace(|| "finalize"))
    }
}

pub fn get_padding(preimage_words: usize) -> Vec<u32> {
    let preimage_bits = preimage_words as u64 * 32;

    // The padding scheme requires that there are at least 3 unutilized words in the preimage's last
    // block: one word to append a `1` bit onto the end of the preimage and two words to append the
    // unpadded preimage's bit length. If there is less than 3 unutilized words in the preimage's
    // last block, pad until the end of the next block.
    let last_block_words = preimage_words % BLOCK_SIZE;
    let unused_words = BLOCK_SIZE - last_block_words;
    let pad_words = if unused_words >= 3 {
        unused_words
    } else {
        unused_words + BLOCK_SIZE
    };

    let mut padding = vec![0u32; pad_words];
    padding[0] = 1 << 31;
    padding[pad_words - 2] = (preimage_bits >> 32) as u32;
    padding[pad_words - 1] = preimage_bits as u32;
    padding
}

#[derive(Clone, Debug)]
pub struct Sha256Config<F: FieldExt> {
    lookup: SpreadTableConfig,
    message_schedule: MessageScheduleConfig<F>,
    compression: CompressionConfig<F>,
    // Equality enabled advice.
    advice: [Column<Advice>; DIGEST_SIZE],
    // Adds (mod 2^32) two words from a compression's input and output states.
    s_add_state_words: Selector,
}

#[derive(Clone, Debug)]
pub struct Sha256Chip<F: FieldExt> {
    config: Sha256Config<F>,
}

impl<F: FieldExt> Chip<F> for Sha256Chip<F> {
    type Config = Sha256Config<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ColumnCount for Sha256Chip<F> {
    fn num_cols() -> NumCols {
        NumCols {
            advice_eq: 8,
            advice_neq: 0,
            fixed_eq: 0,
            fixed_neq: 0,
        }
    }
}

impl<F: FieldExt> Sha256Chip<F> {
    pub fn construct(config: Sha256Config<F>) -> Self {
        Sha256Chip { config }
    }

    /// Loads the lookup table required by this chip into the circuit.
    pub fn load(layouter: &mut impl Layouter<F>, config: &Sha256Config<F>) -> Result<(), Error> {
        SpreadTableChip::load(config.lookup.clone(), layouter)
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 8],
    ) -> Sha256Config<F> {
        // Lookup table inputs cannot be repurposed by the caller; create those columns here and store
        // them privately.
        let input_tag = meta.advice_column();
        let input_dense = meta.advice_column();
        let input_spread = meta.advice_column();

        meta.enable_equality(input_dense);
        meta.enable_equality(input_spread);
        for col in advice.iter() {
            meta.enable_equality(*col);
        }

        // Rename these here for ease of matching the gates to the specification.
        let _a_0 = input_tag;
        let _a_1 = input_dense;
        let _a_2 = input_spread;
        let [a_3, a_4, a_5, a_6, a_7, a_8, a_9, ..] = advice;

        let lookup = SpreadTableChip::configure(meta, input_tag, input_dense, input_spread);

        let compression = CompressionConfig::configure(
            meta,
            lookup.input.clone(),
            [a_3, a_4, a_5, a_6, a_7, a_8, a_9],
        );

        let message_schedule = a_5;

        let message_schedule = MessageScheduleConfig::configure(
            meta,
            lookup.input.clone(),
            message_schedule,
            [a_3, a_4, a_6, a_7, a_8, a_9],
        );

        let s_add_state_words = meta.selector();
        meta.create_gate("add_compression_state_words", |meta| {
            let s = meta.query_selector(s_add_state_words);

            // Compression input/output state word's low/high 16-bit halves, i.e.
            // `input_word = in_lo(2^16)^0 + in_hi(2^16)^1`.
            let in_lo = meta.query_advice(advice[0], Rotation::cur());
            let in_hi = meta.query_advice(advice[1], Rotation::cur());
            let out_lo = meta.query_advice(advice[2], Rotation::cur());
            let out_hi = meta.query_advice(advice[3], Rotation::cur());

            // The sum of the input and output states' 32-bit words is a 33-bit integer decomposed
            // into low/high base-2^32 digits, i.e. `sum = sum_lo(2^32)^0 + sum_hi(2^32)^1`.
            let sum_lo = meta.query_advice(advice[4], Rotation::cur());
            let sum_hi = meta.query_advice(advice[5], Rotation::cur());

            // 32-bit input/output state words.
            let two_pow_16 = F::from(1u64 << 16);
            let word_in = in_lo + in_hi * Expression::Constant(two_pow_16);
            let word_out = out_lo + out_hi * Expression::Constant(two_pow_16);

            // 33-bit input/output state words.
            let sum = sum_lo + sum_hi * Expression::Constant(F::from(1u64 << 32));

            [(
                "compression_input_state_word + compression_output_state_word",
                s * (word_in + word_out - sum),
            )]
        });

        Sha256Config {
            lookup,
            message_schedule,
            compression,
            advice,
            s_add_state_words,
        }
    }

    /// Assign the padding for an assigned, but not yet padded, preimage.
    fn assign_padding(
        &self,
        layouter: &mut impl Layouter<F>,
        unpadded_preimage_word_len: usize,
    ) -> Result<Vec<AssignedBits<F, 32>>, Error> {
        layouter.assign_region(
            || "assign padding",
            |mut region| {
                let mut advice_iter = AdviceIter::from(self.config.advice.to_vec());
                get_padding(unpadded_preimage_word_len)
                    .iter()
                    .enumerate()
                    .map(|(i, pad_word)| {
                        let (offset, col) = advice_iter.next();
                        AssignedBits::<F, 32>::assign(
                            &mut region,
                            || format!("padding word {}", i),
                            col,
                            offset,
                            Value::known(*pad_word),
                        )
                    })
                    .collect()
            },
        )
    }

    fn initialization_vector(&self, layouter: &mut impl Layouter<F>) -> Result<State<F>, Error> {
        self.config.compression.initialize_with_iv(layouter, IV)
    }

    fn compress(
        &self,
        layouter: &mut impl Layouter<F>,
        initialized_state: State<F>,
        input: [AssignedBits<F, 32>; BLOCK_SIZE],
    ) -> Result<State<F>, Error> {
        let (_, w_halves) = self
            .config
            .message_schedule
            .process_assigned(layouter, input)?;
        self.config
            .compression
            .compress(layouter, initialized_state, w_halves)
    }

    fn add_compression_states(
        &self,
        layouter: &mut impl Layouter<F>,
        state_in: State<F>,
        state_out: State<F>,
    ) -> Result<[AssignedBits<F, 32>; STATE], Error> {
        layouter.assign_region(
            || "add compression's input and output states",
            |mut region| {
                let mut offset = 0;

                let (a_in, b_in, c_in, d_in, e_in, f_in, g_in, h_in) =
                    match_state(state_in.clone());
                let (a_out, b_out, c_out, d_out, e_out, f_out, g_out, h_out) =
                    match_state(state_out.clone());

                // Copy input/output `a`'s low/high 16-bit halves.
                self.config.s_add_state_words.enable(&mut region, offset)?;
                a_in.dense_halves.0.copy_advice(
                    || "copy a_in_lo",
                    &mut region,
                    self.config.advice[0],
                    offset,
                )?;
                a_in.dense_halves.1.copy_advice(
                    || "copy a_in_hi",
                    &mut region,
                    self.config.advice[1],
                    offset,
                )?;
                a_out.dense_halves.0.copy_advice(
                    || "copy a_out_lo",
                    &mut region,
                    self.config.advice[2],
                    offset,
                )?;
                a_out.dense_halves.1.copy_advice(
                    || "copy a_out_hi",
                    &mut region,
                    self.config.advice[3],
                    offset,
                )?;
                let a_sum = a_in
                    .dense_halves
                    .value()
                    .zip(a_out.dense_halves.value())
                    .map(|(a_in, a_out)| a_in as u64 + a_out as u64);
                // Assign the sum `a_in + a_out = a_lo + a_hi` as two base-2^32 digits.
                let a_lo = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "a_lo",
                    self.config.advice[4],
                    offset,
                    a_sum.map(|a_sum| a_sum as u32),
                )?;
                let _a_hi = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "a_hi",
                    self.config.advice[5],
                    offset,
                    a_sum.map(|a_sum| (a_sum >> 32) as u32),
                )?;
                offset += 1;

                // Copy input/output `b`'s low/high 16-bit halves.
                self.config.s_add_state_words.enable(&mut region, offset)?;
                b_in.dense_halves.0.copy_advice(
                    || "copy b_in_lo",
                    &mut region,
                    self.config.advice[0],
                    offset,
                )?;
                b_in.dense_halves.1.copy_advice(
                    || "copy b_in_hi",
                    &mut region,
                    self.config.advice[1],
                    offset,
                )?;
                b_out.dense_halves.0.copy_advice(
                    || "copy b_out_lo",
                    &mut region,
                    self.config.advice[2],
                    offset,
                )?;
                b_out.dense_halves.1.copy_advice(
                    || "copy b_out_hi",
                    &mut region,
                    self.config.advice[3],
                    offset,
                )?;
                let b_sum = b_in
                    .dense_halves
                    .value()
                    .zip(b_out.dense_halves.value())
                    .map(|(b_in, b_out)| b_in as u64 + b_out as u64);
                // Assign the sum `b_in + b_out = b_lo + b_hi` as two base-2^32 digits.
                let b_lo = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "b_lo",
                    self.config.advice[4],
                    offset,
                    b_sum.map(|b_sum| b_sum as u32),
                )?;
                let _b_hi = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "b_hi",
                    self.config.advice[5],
                    offset,
                    b_sum.map(|b_sum| (b_sum >> 32) as u32),
                )?;
                offset += 1;

                // Copy input/output `c`'s low/high 16-bit halves.
                self.config.s_add_state_words.enable(&mut region, offset)?;
                c_in.dense_halves.0.copy_advice(
                    || "copy c_in_lo",
                    &mut region,
                    self.config.advice[0],
                    offset,
                )?;
                c_in.dense_halves.1.copy_advice(
                    || "copy c_in_hi",
                    &mut region,
                    self.config.advice[1],
                    offset,
                )?;
                c_out.dense_halves.0.copy_advice(
                    || "copy c_out_lo",
                    &mut region,
                    self.config.advice[2],
                    offset,
                )?;
                c_out.dense_halves.1.copy_advice(
                    || "copy c_out_hi",
                    &mut region,
                    self.config.advice[3],
                    offset,
                )?;
                let c_sum = c_in
                    .dense_halves
                    .value()
                    .zip(c_out.dense_halves.value())
                    .map(|(c_in, c_out)| c_in as u64 + c_out as u64);
                // Assign the sum `c_in + c_out = c_lo + c_hi` as two base-2^32 digits.
                let c_lo = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "c_lo",
                    self.config.advice[4],
                    offset,
                    c_sum.map(|c_sum| c_sum as u32),
                )?;
                let _c_hi = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "c_hi",
                    self.config.advice[5],
                    offset,
                    c_sum.map(|c_sum| (c_sum >> 32) as u32),
                )?;
                offset += 1;

                // Copy input/output `d`'s low/high 16-bit halves.
                self.config.s_add_state_words.enable(&mut region, offset)?;
                d_in.0.copy_advice(
                    || "copy d_in_lo",
                    &mut region,
                    self.config.advice[0],
                    offset,
                )?;
                d_in.1.copy_advice(
                    || "copy d_in_hi",
                    &mut region,
                    self.config.advice[1],
                    offset,
                )?;
                d_out.0.copy_advice(
                    || "copy d_out_lo",
                    &mut region,
                    self.config.advice[2],
                    offset,
                )?;
                d_out.1.copy_advice(
                    || "copy d_out_hi",
                    &mut region,
                    self.config.advice[3],
                    offset,
                )?;
                let d_sum = d_in
                    .value()
                    .zip(d_out.value())
                    .map(|(d_in, d_out)| d_in as u64 + d_out as u64);
                // Assign the sum `d_in + d_out = d_lo + d_hi` as two base-2^32 digits.
                let d_lo = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "d_lo",
                    self.config.advice[4],
                    offset,
                    d_sum.map(|d_sum| d_sum as u32),
                )?;
                let _d_hi = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "d_hi",
                    self.config.advice[5],
                    offset,
                    d_sum.map(|d_sum| (d_sum >> 32) as u32),
                )?;
                offset += 1;

                // Copy input/output `e`'s low/high 16-bit halves.
                self.config.s_add_state_words.enable(&mut region, offset)?;
                e_in.dense_halves.0.copy_advice(
                    || "copy e_in_lo",
                    &mut region,
                    self.config.advice[0],
                    offset,
                )?;
                e_in.dense_halves.1.copy_advice(
                    || "copy e_in_hi",
                    &mut region,
                    self.config.advice[1],
                    offset,
                )?;
                e_out.dense_halves.0.copy_advice(
                    || "copy e_out_lo",
                    &mut region,
                    self.config.advice[2],
                    offset,
                )?;
                e_out.dense_halves.1.copy_advice(
                    || "copy e_out_hi",
                    &mut region,
                    self.config.advice[3],
                    offset,
                )?;
                let e_sum = e_in
                    .dense_halves
                    .value()
                    .zip(e_out.dense_halves.value())
                    .map(|(e_in, e_out)| e_in as u64 + e_out as u64);
                // Assign the sum `e_in + e_out = e_lo + e_hi` as two base-2^32 digits.
                let e_lo = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "e_lo",
                    self.config.advice[4],
                    offset,
                    e_sum.map(|e_sum| e_sum as u32),
                )?;
                let _e_hi = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "e_hi",
                    self.config.advice[5],
                    offset,
                    e_sum.map(|e_sum| (e_sum >> 32) as u32),
                )?;
                offset += 1;

                // Copy input/output `f`'s low/high 16-bit halves.
                self.config.s_add_state_words.enable(&mut region, offset)?;
                f_in.dense_halves.0.copy_advice(
                    || "copy f_in_lo",
                    &mut region,
                    self.config.advice[0],
                    offset,
                )?;
                f_in.dense_halves.1.copy_advice(
                    || "copy f_in_hi",
                    &mut region,
                    self.config.advice[1],
                    offset,
                )?;
                f_out.dense_halves.0.copy_advice(
                    || "copy f_out_lo",
                    &mut region,
                    self.config.advice[2],
                    offset,
                )?;
                f_out.dense_halves.1.copy_advice(
                    || "copy f_out_hi",
                    &mut region,
                    self.config.advice[3],
                    offset,
                )?;
                let f_sum = f_in
                    .dense_halves
                    .value()
                    .zip(f_out.dense_halves.value())
                    .map(|(f_in, f_out)| f_in as u64 + f_out as u64);
                // Assign the sum `f_in + f_out = f_lo + f_hi` as two base-2^32 digits.
                let f_lo = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "f_lo",
                    self.config.advice[4],
                    offset,
                    f_sum.map(|f_sum| f_sum as u32),
                )?;
                let _f_hi = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "f_hi",
                    self.config.advice[5],
                    offset,
                    f_sum.map(|f_sum| (f_sum >> 32) as u32),
                )?;
                offset += 1;

                // Copy input/output `g`'s low/high 16-bit halves.
                self.config.s_add_state_words.enable(&mut region, offset)?;
                g_in.dense_halves.0.copy_advice(
                    || "copy g_in_lo",
                    &mut region,
                    self.config.advice[0],
                    offset,
                )?;
                g_in.dense_halves.1.copy_advice(
                    || "copy g_in_hi",
                    &mut region,
                    self.config.advice[1],
                    offset,
                )?;
                g_out.dense_halves.0.copy_advice(
                    || "copy g_out_lo",
                    &mut region,
                    self.config.advice[2],
                    offset,
                )?;
                g_out.dense_halves.1.copy_advice(
                    || "copy g_out_hi",
                    &mut region,
                    self.config.advice[3],
                    offset,
                )?;
                let g_sum = g_in
                    .dense_halves
                    .value()
                    .zip(g_out.dense_halves.value())
                    .map(|(g_in, g_out)| g_in as u64 + g_out as u64);
                // Assign the sum `g_in + g_out = g_lo + g_hi` as two base-2^32 digits.
                let g_lo = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "g_lo",
                    self.config.advice[4],
                    offset,
                    g_sum.map(|g_sum| g_sum as u32),
                )?;
                let _g_hi = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "g_hi",
                    self.config.advice[5],
                    offset,
                    g_sum.map(|g_sum| (g_sum >> 32) as u32),
                )?;
                offset += 1;

                // Copy input/output `h`'s low/high 16-bit halves.
                self.config.s_add_state_words.enable(&mut region, offset)?;
                h_in.0.copy_advice(
                    || "copy h_in_lo",
                    &mut region,
                    self.config.advice[0],
                    offset,
                )?;
                h_in.1.copy_advice(
                    || "copy h_in_hi",
                    &mut region,
                    self.config.advice[1],
                    offset,
                )?;
                h_out.0.copy_advice(
                    || "copy h_out_lo",
                    &mut region,
                    self.config.advice[2],
                    offset,
                )?;
                h_out.1.copy_advice(
                    || "copy h_out_hi",
                    &mut region,
                    self.config.advice[3],
                    offset,
                )?;
                let h_sum = h_in
                    .value()
                    .zip(h_out.value())
                    .map(|(h_in, h_out)| h_in as u64 + h_out as u64);
                // Assign the sum `h_in + h_out = h_lo + h_hi` as two base-2^32 digits.
                let h_lo = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "h_lo",
                    self.config.advice[4],
                    offset,
                    h_sum.map(|h_sum| h_sum as u32),
                )?;
                let _h_hi = AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "h_hi",
                    self.config.advice[5],
                    offset,
                    h_sum.map(|h_sum| (h_sum >> 32) as u32),
                )?;

                Ok([a_lo, b_lo, c_lo, d_lo, e_lo, f_lo, g_lo, h_lo])
            },
        )
    }

    #[allow(clippy::many_single_char_names)]
    fn add_compression_states_then_intialize(
        &self,
        layouter: &mut impl Layouter<F>,
        state_in: State<F>,
        state_out: State<F>,
    ) -> Result<State<F>, Error> {
        let [a, b, c, d, e, f, g, h] =
            self.add_compression_states(layouter, state_in, state_out)?;

        layouter.assign_region(
            || "initialize_with_state",
            |mut region| {
                let [.., a_7, _a_8, _a_9] = self.config.compression.advice;
                // TODO (jake): shouldn't initialization use `AssignedBits<F, 32>` rather than `Option<u32>`?
                let e = self.config.compression.decompose_e(
                    &mut region,
                    RoundIdx::Init,
                    e.value_u32(),
                )?;
                let f = self.config.compression.decompose_f(
                    &mut region,
                    RoundIdx::Init,
                    f.value_u32(),
                )?;
                let g = self.config.compression.decompose_g(
                    &mut region,
                    RoundIdx::Init,
                    g.value_u32(),
                )?;
                let h_row = get_h_row(RoundIdx::Init);
                let h = self.config.compression.assign_word_halves_dense(
                    &mut region,
                    h_row,
                    a_7,
                    h_row + 1,
                    a_7,
                    h.value_u32(),
                )?;
                let a = self.config.compression.decompose_a(
                    &mut region,
                    RoundIdx::Init,
                    a.value_u32(),
                )?;
                let b = self.config.compression.decompose_b(
                    &mut region,
                    RoundIdx::Init,
                    b.value_u32(),
                )?;
                let c = self.config.compression.decompose_c(
                    &mut region,
                    RoundIdx::Init,
                    c.value_u32(),
                )?;
                let d_row = get_d_row(RoundIdx::Init);
                let d = self.config.compression.assign_word_halves_dense(
                    &mut region,
                    d_row,
                    a_7,
                    d_row + 1,
                    a_7,
                    d.value_u32(),
                )?;
                Ok(State::new(
                    StateWord::A(a),
                    StateWord::B(b),
                    StateWord::C(c),
                    StateWord::D(d),
                    StateWord::E(e),
                    StateWord::F(f),
                    StateWord::G(g),
                    StateWord::H(h),
                ))
            },
        )
    }

    /// Hash without padding `preimage`; `preimage` must must be assigned in columns which are
    /// equality enabled.
    pub fn hash_nopad(
        &self,
        mut layouter: impl Layouter<F>,
        preimage: &[AssignedBits<F, 32>],
    ) -> Result<[AssignedBits<F, 32>; DIGEST_SIZE], Error> {
        assert_eq!(
            preimage.len() % BLOCK_SIZE,
            0,
            "preimage length must be divisible by block size",
        );

        let blocks: Vec<[AssignedBits<F, 32>; BLOCK_SIZE]> = preimage
            .chunks(BLOCK_SIZE)
            .map(|block| block.to_vec().try_into().unwrap())
            .collect();

        let num_blocks = blocks.len();

        // Process the first block.
        let mut state_in = self.initialization_vector(&mut layouter)?;
        let mut state_out = self.compress(&mut layouter, state_in.clone(), blocks[0].clone())?;
        if num_blocks == 1 {
            return self.add_compression_states(&mut layouter, state_in, state_out);
        }

        // Process all remaining blocks except for the last.
        for block in &blocks[1..num_blocks - 1] {
            state_in = self.add_compression_states_then_intialize(
                &mut layouter,
                state_in.clone(),
                state_out.clone(),
            )?;
            state_out = self.compress(&mut layouter, state_in.clone(), block.clone())?;
        }

        // Process the last block.
        state_in = self.add_compression_states_then_intialize(
            &mut layouter,
            state_in.clone(),
            state_out.clone(),
        )?;
        state_out = self.compress(
            &mut layouter,
            state_in.clone(),
            blocks[num_blocks - 1].clone(),
        )?;
        self.add_compression_states(&mut layouter, state_in, state_out)
    }

    /// Hash `preimage`; `preimage` must must be assigned in columns which are equality enabled.
    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        preimage: &[AssignedBits<F, 32>],
    ) -> Result<[AssignedBits<F, 32>; DIGEST_SIZE], Error> {
        let preimage_words_len = preimage.len();
        let padding = self.assign_padding(&mut layouter, preimage_words_len)?;

        let mut padded_preimage = Vec::with_capacity(preimage_words_len + padding.len());
        padded_preimage.extend_from_slice(preimage);
        padded_preimage.extend_from_slice(&padding);

        self.hash_nopad(layouter, &padded_preimage)
    }
}

#[derive(Clone, Debug)]
pub struct Sha256FieldConfig<F: FieldExt> {
    sha256: Sha256Config<F>,
    // Field element to/from sha256 words conversion.
    sha256_words: Sha256WordsConfig<F>,
}

#[derive(Clone, Debug)]
pub struct Sha256FieldChip<F: FieldExt> {
    config: Sha256FieldConfig<F>,
}

impl<F: FieldExt> Chip<F> for Sha256FieldChip<F> {
    type Config = Sha256FieldConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ColumnCount for Sha256FieldChip<F> {
    fn num_cols() -> NumCols {
        NumCols {
            advice_eq: 9,
            advice_neq: 0,
            fixed_eq: 0,
            fixed_neq: 0,
        }
    }
}

impl<F: FieldExt> Sha256FieldChip<F> {
    pub fn construct(config: Sha256FieldConfig<F>) -> Self {
        Sha256FieldChip { config }
    }

    /// Loads the lookup table required by this chip into the circuit.
    pub fn load(
        layouter: &mut impl Layouter<F>,
        config: &Sha256FieldConfig<F>,
    ) -> Result<(), Error> {
        Sha256Chip::load(layouter, &config.sha256)
    }

    // # Side Effects
    //
    // `advice` will be equality enabled.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 9],
    ) -> Sha256FieldConfig<F> {
        let sha256 = Sha256Chip::configure(meta, advice[..8].try_into().unwrap());
        let sha256_words = Sha256WordsChip::configure(meta, advice);
        Sha256FieldConfig {
            sha256,
            sha256_words,
        }
    }

    pub fn hash_words_nopad(
        &self,
        layouter: impl Layouter<F>,
        preimage: &[AssignedBits<F, 32>],
    ) -> Result<[AssignedBits<F, 32>; DIGEST_SIZE], Error> {
        Sha256Chip::construct(self.config.sha256.clone()).hash_nopad(layouter, preimage)
    }

    pub fn hash_words(
        &self,
        layouter: impl Layouter<F>,
        preimage: &[AssignedBits<F, 32>],
    ) -> Result<[AssignedBits<F, 32>; DIGEST_SIZE], Error> {
        Sha256Chip::construct(self.config.sha256.clone()).hash(layouter, preimage)
    }

    pub fn hash_field_elems(
        &self,
        mut layouter: impl Layouter<F>,
        preimage: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        let words_chip = Sha256WordsChip::construct(self.config.sha256_words.clone());

        // Assign preimage as sha256 words.
        let mut preimage_words = Vec::with_capacity(preimage.len() * FIELD_WORD_LEN);
        for (i, elem) in preimage.iter().enumerate() {
            let words = words_chip.into_words(
                layouter.namespace(|| format!("preimage elem {} into words", i)),
                elem.clone(),
            )?;
            preimage_words.extend(words);
        }

        // Compute digest.
        let digest_words = Sha256Chip::construct(self.config.sha256.clone())
            .hash(layouter.namespace(|| "sha256"), &preimage_words)?;

        // Pack digest words into a field element.
        words_chip.pack_digest(layouter.namespace(|| "pack digest"), &digest_words)
    }

    pub fn pack_digest(
        &self,
        layouter: impl Layouter<F>,
        digest_words: &[AssignedBits<F, 32>; 8],
    ) -> Result<AssignedCell<F, F>, Error> {
        Sha256WordsChip::construct(self.config.sha256_words.clone())
            .pack_digest(layouter, digest_words)
    }
}

#[derive(Clone, Debug)]
pub struct Sha256WordsConfig<F: FieldExt> {
    // Equality enabled advice.
    advice: [Column<Advice>; 9],
    // Decomposes a field element in eight little-endian `u32`s.
    s_field_into_u32s: Selector,
    // Changes a `u32`'s byte order from little to big endian.
    s_u32_reverse_bytes: Selector,
    // Strips the two most significant bits from a `u32`.
    strip_bits: StripBitsConfig<F>,
}

#[derive(Debug)]
pub struct Sha256WordsChip<F: FieldExt> {
    config: Sha256WordsConfig<F>,
}

impl<F: FieldExt> Chip<F> for Sha256WordsChip<F> {
    type Config = Sha256WordsConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ColumnCount for Sha256WordsChip<F> {
    fn num_cols() -> NumCols {
        NumCols {
            advice_eq: 9,
            advice_neq: 0,
            fixed_eq: 0,
            fixed_neq: 0,
        }
    }
}

impl<F: FieldExt> Sha256WordsChip<F> {
    pub fn construct(config: Sha256WordsConfig<F>) -> Self {
        Sha256WordsChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 9],
    ) -> Sha256WordsConfig<F> {
        let strip_bits = StripBitsChip::configure(meta, advice);

        let s_field_into_u32s = meta.selector();
        {
            // `[2^32, (2^32)^2, .., (2^32)^7]`
            let mut radix_pows = Vec::with_capacity(7);
            let radix = F::from(1u64 << 32);
            radix_pows.push(radix);
            for i in 0..6 {
                radix_pows.push(radix_pows[i] * radix);
            }

            meta.create_gate("field_into_u32s", |meta| {
                let s = meta.query_selector(s_field_into_u32s);
                let field = meta.query_advice(advice[0], Rotation::cur());

                let mut expr = meta.query_advice(advice[1], Rotation::cur());
                for (col, radix_pow) in advice[2..].iter().zip(radix_pows.iter()) {
                    let uint32 = meta.query_advice(*col, Rotation::cur());
                    expr = expr + Expression::Constant(*radix_pow) * uint32;
                }

                [s * (expr - field)]
            });
        }

        let s_u32_reverse_bytes = meta.selector();
        {
            // `[(2^8)^1, ..., (2^8)^3]`
            let mut radix_pows = Vec::with_capacity(3);
            let radix = F::from(256);
            radix_pows.push(radix);
            for i in 0..3 {
                radix_pows.push(radix_pows[i] * radix);
            }

            meta.create_gate("u32_reverse_bytes", |meta| {
                let s = meta.query_selector(s_u32_reverse_bytes);
                let u32_le = meta.query_advice(advice[0], Rotation::cur());

                // The `u32`'s four little-endian bytes.
                let le_bytes = [
                    meta.query_advice(advice[1], Rotation::cur()),
                    meta.query_advice(advice[2], Rotation::cur()),
                    meta.query_advice(advice[3], Rotation::cur()),
                    meta.query_advice(advice[4], Rotation::cur()),
                ];

                let u32_be = meta.query_advice(advice[5], Rotation::cur());

                // `u32`'s little-endian byte decomposition.
                let le_expr = le_bytes[0].clone()
                    + le_bytes[1].clone() * Expression::Constant(radix_pows[0])
                    + le_bytes[2].clone() * Expression::Constant(radix_pows[1])
                    + le_bytes[3].clone() * Expression::Constant(radix_pows[2]);

                // `u32`'s big-endian byte decomposition.
                let be_expr = le_bytes[3].clone()
                    + le_bytes[2].clone() * Expression::Constant(radix_pows[0])
                    + le_bytes[1].clone() * Expression::Constant(radix_pows[1])
                    + le_bytes[0].clone() * Expression::Constant(radix_pows[2]);

                [
                    ("u32 le-bytes decomp", s.clone() * (u32_le - le_expr)),
                    ("u32 be-bytes decomp", s * (u32_be - be_expr)),
                ]
            });
        }

        Sha256WordsConfig {
            advice,
            strip_bits,
            s_field_into_u32s,
            s_u32_reverse_bytes,
        }
    }

    fn u32_decomp(
        &self,
        layouter: &mut impl Layouter<F>,
        field: WitnessOrCopy<F, F>,
    ) -> Result<[AssignedBits<F, 32>; 8], Error> {
        layouter.assign_region(
            || "decompose field element into eight u32s",
            |mut region| {
                let offset = 0;
                self.config.s_field_into_u32s.enable(&mut region, offset)?;

                // Witness or copy the field element to be decomposed.
                let field = match field {
                    WitnessOrCopy::Witness(field) => region.assign_advice(
                        || "witness field element",
                        self.config.advice[0],
                        offset,
                        || field,
                    )?,
                    WitnessOrCopy::Copy(ref field) => field.copy_advice(
                        || "copy field element",
                        &mut region,
                        self.config.advice[0],
                        offset,
                    )?,
                    WitnessOrCopy::PiCopy(pi_col, pi_row) => region.assign_advice_from_instance(
                        || "copy field element public input",
                        pi_col,
                        pi_row,
                        self.config.advice[0],
                        offset,
                    )?,
                };

                let repr = field.value().map(|field| field.to_repr());

                // Assign `u32` decomposition.
                let le_u32s = self.config.advice[1..]
                    .iter()
                    .enumerate()
                    .map(|(i, col)| {
                        let uint32: Value<u32> = repr.map(|repr| {
                            let le_bytes = &repr.as_ref()[i * 4..(i + 1) * 4];
                            u32::from_le_bytes(le_bytes.try_into().unwrap())
                        });
                        AssignedBits::<F, 32>::assign(
                            &mut region,
                            || format!("u32_{}", i),
                            *col,
                            offset,
                            uint32,
                        )
                    })
                    .collect::<Result<Vec<AssignedBits<F, 32>>, Error>>()?;

                Ok(le_u32s.try_into().unwrap())
            },
        )
    }

    fn u32_reverse_bytes(
        &self,
        mut layouter: impl Layouter<F>,
        word: &AssignedBits<F, 32>,
    ) -> Result<AssignedBits<F, 32>, Error> {
        layouter.assign_region(
            || "u32 reverse bytes",
            |mut region| {
                let offset = 0;
                self.config
                    .s_u32_reverse_bytes
                    .enable(&mut region, offset)?;

                // Copy `u32`.
                word.copy_advice(|| "copy word", &mut region, self.config.advice[0], offset)?;

                let le_bytes: [Value<u8>; 4] =
                    word.value_u32().map(u32::to_le_bytes).transpose_array();

                // Assign `words`'s little-endian bytes.
                for (byte_index, (byte, col)) in le_bytes
                    .iter()
                    .zip(&self.config.advice[1..=4])
                    .enumerate()
                {
                    region.assign_advice(
                        || format!("word le-byte {}", byte_index),
                        *col,
                        offset,
                        || byte.map(|byte| F::from(byte as u64)),
                    )?;
                }

                // Assign the `u32` from big-endian bytes.
                AssignedBits::<F, 32>::assign(
                    &mut region,
                    || "word_be",
                    self.config.advice[5],
                    offset,
                    word.value_u32().map(u32::swap_bytes),
                )
            },
        )
    }

    pub fn into_words(
        &self,
        layouter: impl Layouter<F>,
        field: AssignedCell<F, F>,
    ) -> Result<[AssignedU32<F>; 8], Error> {
        self.into_words_inner(layouter, WitnessOrCopy::Copy(field))
    }

    pub fn witness_into_words(
        &self,
        layouter: impl Layouter<F>,
        field: Value<F>,
    ) -> Result<[AssignedU32<F>; 8], Error> {
        self.into_words_inner(layouter, WitnessOrCopy::Witness(field))
    }

    pub fn pi_into_words(
        &self,
        layouter: impl Layouter<F>,
        pi_col: Column<Instance>,
        // Absolute row.
        pi_row: usize,
    ) -> Result<[AssignedU32<F>; 8], Error> {
        self.into_words_inner(layouter, WitnessOrCopy::PiCopy(pi_col, pi_row))
    }

    #[allow(clippy::wrong_self_convention)]
    fn into_words_inner(
        &self,
        mut layouter: impl Layouter<F>,
        field: WitnessOrCopy<F, F>,
    ) -> Result<[AssignedU32<F>; 8], Error> {
        let le_u32s = self.u32_decomp(&mut layouter, field)?;

        let words = le_u32s
            .iter()
            .enumerate()
            .map(|(i, uint32)| {
                self.u32_reverse_bytes(
                    layouter.namespace(|| format!("u32 {} reverse bytes", i)),
                    uint32,
                )
            })
            .collect::<Result<Vec<AssignedBits<F, 32>>, Error>>()?;

        Ok(words.try_into().unwrap())
    }

    pub fn pack_digest(
        &self,
        mut layouter: impl Layouter<F>,
        digest_words: &[AssignedBits<F, 32>; 8],
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut reordered_words = digest_words
            .iter()
            .enumerate()
            .map(|(word_index, word)| {
                self.u32_reverse_bytes(
                    layouter.namespace(|| format!("reverse digest word {} bytes", word_index)),
                    word,
                )
            })
            .collect::<Result<Vec<AssignedBits<F, 32>>, Error>>()?;

        reordered_words[7] = StripBitsChip::construct(self.config.strip_bits.clone()).strip_bits(
            layouter.namespace(|| "strip bits from digest"),
            &reordered_words[7],
        )?;

        // Pack the reorderd words into a field element.
        layouter.assign_region(
            || "pack reordered words into field element",
            |mut region| {
                let offset = 0;
                self.config.s_field_into_u32s.enable(&mut region, offset)?;

                let mut packed_repr = Value::known(F::Repr::default());

                for (word_index, (word, col)) in reordered_words
                    .iter()
                    .zip(&self.config.advice[1..])
                    .enumerate()
                {
                    word
                        .copy_advice(
                            || format!("copy reordered word {}", word_index),
                            &mut region,
                            *col,
                            offset,
                        )
                        .map(AssignedBits::<F, 32>)?
                        .value_u32()
                        .zip(packed_repr.as_mut())
                        .map(|(word, repr)| {
                            repr
                                .as_mut()[word_index * 4..(word_index + 1) * 4]
                                .copy_from_slice(&word.to_le_bytes());
                        });
                }

                region.assign_advice(
                    || "pack reordered words into field element",
                    self.config.advice[0],
                    offset,
                    || {
                        packed_repr
                            .map(|repr| F::from_repr_vartime(repr)
                            .expect("words are invalid field element"))
                    },
                )
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::PrimeField;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        pasta::{EqAffine, Fp},
        plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, SingleVerifier},
        poly::commitment::Params,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};

    use crate::AdviceIter;

    #[test]
    fn test_sha256_hash_words_nopad() {
        #[derive(Clone)]
        struct MyConfig<F: FieldExt> {
            sha256: Sha256Config<F>,
            advice: [Column<Advice>; 8],
        }

        struct MyCircuit {
            preimage: [Value<u32>; BLOCK_SIZE],
            expected_digest: [Value<u32>; DIGEST_SIZE],
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    preimage: [Value::unknown(); BLOCK_SIZE],
                    expected_digest: [Value::unknown(); DIGEST_SIZE],
                }
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
                ];
                let sha256 = Sha256Chip::configure(meta, advice);
                MyConfig { sha256, advice }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let MyConfig {
                    sha256: sha256_config,
                    advice,
                } = config;

                Sha256Chip::load(&mut layouter, &sha256_config)?;
                let sha256_chip = Sha256Chip::construct(sha256_config);

                let preimage = layouter.assign_region(
                    || "assign preimage",
                    |mut region| {
                        let mut advice_iter = AdviceIter::from(advice.to_vec());
                        self.preimage
                            .iter()
                            .enumerate()
                            .map(|(i, word)| {
                                let (offset, col) = advice_iter.next();
                                AssignedBits::<F, 32>::assign(
                                    &mut region,
                                    || format!("preimage word {}", i),
                                    col,
                                    offset,
                                    *word,
                                )
                            })
                            .collect::<Result<Vec<AssignedBits<F, 32>>, Error>>()
                    },
                )?;

                let digest_words =
                    sha256_chip.hash_nopad(layouter.namespace(|| "sha256"), &preimage)?;

                for (word, expected_word) in digest_words.iter().zip(self.expected_digest.iter()) {
                    word
                        .value_u32()
                        .zip(expected_word.as_ref())
                        .assert_if_known(|(word, expected_word)| word == *expected_word);
                }

                Ok(())
            }
        }

        // "abcd"
        let preimage_bytes = vec![97u8, 98, 99, 100];

        // Only tests preimages of 32-bit words.
        assert_eq!(preimage_bytes.len() % 4, 0);

        let unpadded_preimage: Vec<Value<u32>> = preimage_bytes
            .chunks(4)
            .map(|bytes| Value::known(u32::from_be_bytes(bytes.try_into().unwrap())))
            .collect();

        let padded_preimage: [Value<u32>; BLOCK_SIZE] = {
            let mut padded_preimage = Vec::with_capacity(BLOCK_SIZE);
            padded_preimage.extend_from_slice(&unpadded_preimage);
            for pad_word in get_padding(unpadded_preimage.len()) {
                padded_preimage.push(Value::known(pad_word));
            }
            // Only test preimages of one block.
            assert_eq!(padded_preimage.len(), BLOCK_SIZE);
            padded_preimage.try_into().unwrap()
        };

        let expected_digest: [Value<u32>; DIGEST_SIZE] = Sha256::digest(&preimage_bytes)
            .chunks(4)
            .map(|bytes| Value::known(u32::from_be_bytes(bytes.try_into().unwrap())))
            .collect::<Vec<Value<u32>>>()
            .try_into()
            .unwrap();

        // Test `Sha256Chip::hash_nopad` (chip caller pads the preimage).
        let circ = MyCircuit {
            preimage: padded_preimage,
            expected_digest,
        };
        let prover = MockProver::<Fp>::run(17, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_sha256_pad_and_hash_words() {
        #[derive(Clone)]
        struct MyConfig<F: FieldExt> {
            sha256: Sha256Config<F>,
            advice: [Column<Advice>; 8],
        }

        struct MyCircuit {
            preimage: Vec<Value<u32>>,
            expected_digest: [Value<u32>; DIGEST_SIZE],
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    preimage: vec![Value::unknown(); self.preimage.len()],
                    expected_digest: [Value::unknown(); DIGEST_SIZE],
                }
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
                ];
                let sha256 = Sha256Chip::configure(meta, advice);
                MyConfig { sha256, advice }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let MyConfig {
                    sha256: sha256_config,
                    advice,
                } = config;

                Sha256Chip::load(&mut layouter, &sha256_config)?;
                let sha256_chip = Sha256Chip::construct(sha256_config);

                let preimage = layouter.assign_region(
                    || "assign preimage",
                    |mut region| {
                        let mut advice_iter = AdviceIter::from(advice.to_vec());
                        self.preimage
                            .iter()
                            .enumerate()
                            .map(|(i, word)| {
                                let (offset, col) = advice_iter.next();
                                AssignedBits::<F, 32>::assign(
                                    &mut region,
                                    || format!("preimage word {}", i),
                                    col,
                                    offset,
                                    *word,
                                )
                            })
                            .collect::<Result<Vec<AssignedBits<F, 32>>, Error>>()
                    },
                )?;

                let digest_words = sha256_chip.hash(layouter.namespace(|| "sha256"), &preimage)?;

                for (word, expected_word) in digest_words.iter().zip(self.expected_digest.iter()) {
                    word
                        .value_u32()
                        .zip(expected_word.as_ref())
                        .assert_if_known(|(word, expected_word)| word == *expected_word);
                }

                Ok(())
            }
        }

        // "a" unicode byte.
        let a = 97u8;

        let preimages = [
            // One block preimage.
            vec![a; 4],
            // One block preimage requiring an additional block of padding.
            vec![a; 64],
            // Two block preimage.
            vec![a; 68],
            // Two block preimage requiring an additional block of padding.
            vec![a; 96],
        ];

        for preimage_bytes in &preimages {
            let preimage_byte_len = preimage_bytes.len();
            assert_eq!(
                preimage_byte_len % 4,
                0,
                "preimage byte length not divisible by word size"
            );

            let unpadded_preimage: Vec<Value<u32>> = preimage_bytes
                .chunks(4)
                .map(|bytes| Value::known(u32::from_be_bytes(bytes.try_into().unwrap())))
                .collect();

            let expected_digest = Sha256::digest(preimage_bytes)
                .chunks(4)
                .map(|bytes| Value::known(u32::from_be_bytes(bytes.try_into().unwrap())))
                .collect::<Vec<Value<u32>>>()
                .try_into()
                .unwrap();

            let circ = MyCircuit {
                preimage: unpadded_preimage,
                expected_digest,
            };

            let prover = MockProver::<Fp>::run(17, &circ, vec![]).unwrap();
            assert!(prover.verify().is_ok());
        }
    }

    #[test]
    fn test_sha256_hash_field_elems() {
        struct MyCircuit;

        impl Circuit<Fp> for MyCircuit {
            type Config = (Sha256FieldConfig<Fp>, [Column<Advice>; 9]);
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
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
                let sha256 = Sha256FieldChip::configure(meta, advice);
                (sha256, advice)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let (sha256_config, advice) = config;

                Sha256FieldChip::load(&mut layouter, &sha256_config)?;
                let sha256_chip = Sha256FieldChip::construct(sha256_config);

                // Test constant preimages against their known digests.

                // "abc"
                let abc = layouter.assign_region(
                    || "assign abc",
                    |mut region| {
                        let offset = 0;
                        region.assign_advice(
                            || "abc",
                            advice[0],
                            offset,
                            || {
                                let mut repr = [0u8; 32];
                                repr[..3].copy_from_slice(&[97u8, 98, 99]);
                                Value::known(Fp::from_repr_vartime(repr).unwrap())
                            },
                        )
                    },
                )?;

                // One block preimage.
                {
                    let preimage = [abc.clone()];

                    let digest_words: Vec<Value<u32>> = sha256_chip
                        .hash_field_elems(layouter.namespace(|| "hash preimage 1"), &preimage)?
                        .value()
                        .map(|field| {
                            field
                                .to_repr()
                                .chunks(4)
                                .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
                                .collect::<Vec<u32>>()
                        })
                        .transpose_vec(8);

                    let expected_digest: [Value<u32>; 8] = [
                        Value::known(0x26426d7c),
                        Value::known(0xb06a1264),
                        Value::known(0x3ccfe841),
                        Value::known(0x07603083),
                        Value::known(0xd835c37f),
                        Value::known(0x000a12f7),
                        Value::known(0x34137a0c),
                        Value::known(0x8df77f26),
                    ];

                    for (word, expected_word) in digest_words.iter().zip(expected_digest.iter()) {
                        word
                            .zip(*expected_word)
                            .assert_if_known(|(word, expected_word)| word == expected_word);
                    }
                }

                // One block preimage requiring an additional block of padding.
                {
                    let preimage = [abc.clone(), abc];

                    let digest_words: Vec<Value<u32>> = sha256_chip
                        .hash_field_elems(layouter.namespace(|| "hash preimage 2"), &preimage)?
                        .value()
                        .map(|field| {
                            field
                                .to_repr()
                                .chunks(4)
                                .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
                                .collect::<Vec<u32>>()
                        })
                        .transpose_vec(8);

                    let expected_digest: [Value<u32>; 8] = [
                        Value::known(0x76629a59),
                        Value::known(0xa5b36f76),
                        Value::known(0x6f1ef203),
                        Value::known(0x8ce1271b),
                        Value::known(0xe300f38f),
                        Value::known(0x737a4316),
                        Value::known(0x87252d8f),
                        Value::known(0x7781af3f),
                    ];

                    for (word, expected_word) in digest_words.iter().zip(expected_digest.iter()) {
                        word
                            .zip(*expected_word)
                            .assert_if_known(|(word, expected_word)| word == expected_word);
                    }
                }

                Ok(())
            }
        }

        let circ = MyCircuit;
        let k = 17;
        let prover = MockProver::<Fp>::run(k, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());

        let params = Params::<EqAffine>::new(k);
        let pk = {
            let vk = keygen_vk(&params, &circ).expect("failed to create verifying key");
            keygen_pk(&params, vk, &circ).expect("failed to create proving key")
        };
        let vk = pk.get_vk();

        type TranscriptReader<'proof> = Blake2bRead<&'proof [u8], EqAffine, Challenge255<EqAffine>>;
        type TranscriptWriter = Blake2bWrite<Vec<u8>, EqAffine, Challenge255<EqAffine>>;

        let mut transcript = TranscriptWriter::init(vec![]);
        create_proof(&params, &pk, &[circ], &[&[]], &mut OsRng, &mut transcript)
            .expect("failed to create halo2 proof");
        let proof_bytes: Vec<u8> = transcript.finalize();

        let mut transcript = TranscriptReader::init(&proof_bytes);
        let verifier_strategy = SingleVerifier::new(&params);
        verify_proof(&params, vk, verifier_strategy, &[&[]], &mut transcript)
            .expect("failed to verify halo2 proof");
    }

    #[test]
    fn test_sha256_field_words_conversion() {
        struct MyCircuit;

        impl Circuit<Fp> for MyCircuit {
            type Config = (Sha256WordsConfig<Fp>, [Column<Advice>; 9]);
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
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
                let sha256_words = Sha256WordsChip::configure(meta, advice);
                (sha256_words, advice)
            }

            #[allow(clippy::unusual_byte_groupings)]
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let (sha256_words_config, advice) = config;

                let sha256_words_chip = Sha256WordsChip::construct(sha256_words_config);

                // Test converting field elements against their known preimage words.

                // `1`
                let words_1: Vec<Value<u32>> = sha256_words_chip
                    .witness_into_words(layouter.namespace(|| "1 into words"), Value::known(Fp::one()))?
                    .iter()
                    .map(|word| word.value_u32())
                    .collect();
                let expected_words_1 = [
                    Value::known(u32::from_be_bytes([1, 0, 0, 0])),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                ];
                for (word, expected_word) in words_1.iter().zip(expected_words_1.iter()) {
                    word
                        .zip(*expected_word)
                        .assert_if_known(|(word, expected_word)| word == expected_word);
                }

                // `2^32 - 1` (first word contains 32 `1` bits).
                let words_2: Vec<Value<u32>> = sha256_words_chip
                    .witness_into_words(
                        layouter.namespace(|| "2^32 - 1 into words"),
                        Value::known(Fp::from((1u64 << 32) - 1)),
                    )?
                    .iter()
                    .map(|word| word.value_u32())
                    .collect();
                let expected_words_2 = [
                    Value::known(u32::max_value()),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                ];
                for (word, expected_word) in words_2.iter().zip(expected_words_2.iter()) {
                    word
                        .zip(*expected_word)
                        .assert_if_known(|(word, expected_word)| word == expected_word);
                }

                // `2^32` (first word contains 32 `0` bits; second word contains one `1` bit).
                let words_3: Vec<Value<u32>> = sha256_words_chip
                    .witness_into_words(
                        layouter.namespace(|| "2^32 into words"),
                        Value::known(Fp::from(1u64 << 32)),
                    )?
                    .iter()
                    .map(|word| word.value_u32())
                    .collect();
                let expected_words_3 = [
                    Value::known(0),
                    Value::known(u32::from_be_bytes([1, 0, 0, 0])),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                ];
                for (word, expected_word) in words_3.iter().zip(expected_words_3.iter()) {
                    word
                        .zip(*expected_word)
                        .assert_if_known(|(word, expected_word)| word == expected_word);
                }

                // `2^66 + 2^72 + 2^95` (first two words each contain 32 `0` bits; third word
                // contains three `1` bits).
                let words_4: Vec<Value<u32>> = {
                    let mut repr = [0u8; 32];
                    // `2^66 + 2^72 + 2^95`
                    repr[8..12]
                        .copy_from_slice(&0b10000000_00000000_00000001_00000100u32.to_le_bytes());
                    sha256_words_chip
                        .witness_into_words(
                            layouter.namespace(|| "2^66 + 2^95 into words"),
                            Value::known(Fp::from_repr_vartime(repr).unwrap()),
                        )?
                        .iter()
                        .map(|word| word.value_u32())
                        .collect()
                };
                let expected_words_4 = [
                    Value::known(0),
                    Value::known(0),
                    Value::known(u32::from_be_bytes([0b100, 1, 0, 0b10000000])),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                    Value::known(0),
                ];
                for (word, expected_word) in words_4.iter().zip(expected_words_4.iter()) {
                    word
                        .zip(*expected_word)
                        .assert_if_known(|(word, expected_word)| word == expected_word);
                }

                // `-1 mod p`
                let neg_1 = Fp::zero() - Fp::one();
                let words_5: Vec<Value<u32>> = sha256_words_chip
                    .witness_into_words(layouter.namespace(|| "-1 into words"), Value::known(neg_1))?
                    .iter()
                    .map(|word| word.value_u32())
                    .collect();
                let expected_words_5: Vec<Value<u32>> = neg_1
                    .to_repr()
                    .as_ref()
                    .chunks(4)
                    .map(|bytes| Value::known(u32::from_be_bytes(bytes.try_into().unwrap())))
                    .collect();
                for (word, expected_word) in words_5.iter().zip(expected_words_5.iter()) {
                    word
                        .zip(*expected_word)
                        .assert_if_known(|(word, expected_word)| word == expected_word);
                }

                // Test packing a sha256 digest (eight 32-bit words) into a field element.

                // The two most significant bits of the last word's least significant byte are `0`
                // to ensure that the packed digest fits within a 255-bit field element.
                let digest_words = [
                    1u32,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    0b11111111_11000000_00001000_00111111,
                ];

                // Set the two bits which should be stripped during packing.
                let last_word_unstripped = digest_words[7] | 0b11000000u32;

                let expected_packed_digest = {
                    let repr: [u8; 32] = digest_words
                        .iter()
                        .copied()
                        .flat_map(u32::to_be_bytes)
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap();
                    Value::known(Fp::from_repr_vartime(repr).unwrap())
                };

                let (digest_1, digest_2) = layouter.assign_region(
                    || "assign digest words",
                    |mut region| {
                        let offset = 0;

                        let digest_1: [AssignedBits<Fp, 32>; 8] = digest_words
                            .iter()
                            .zip(advice[..8].iter())
                            .enumerate()
                            .map(|(word_index, (word, col))| {
                                AssignedBits::<Fp, 32>::assign(
                                    &mut region,
                                    || format!("digest_1 word {}", word_index),
                                    *col,
                                    offset,
                                    Value::known(*word),
                                )
                            })
                            .collect::<Result<Vec<AssignedBits<Fp, 32>>, Error>>()?
                            .try_into()
                            .unwrap();

                        let mut digest_2 = digest_1.clone();
                        digest_2[7] = AssignedBits::<Fp, 32>::assign(
                            &mut region,
                            || "word 7 unstripped",
                            advice[8],
                            offset,
                            Value::known(last_word_unstripped),
                        )?;

                        Ok((digest_1, digest_2))
                    },
                )?;

                // Test packing a 254-bit sha256 digest into a field element.
                sha256_words_chip
                    .pack_digest(layouter.namespace(|| "pack digest_1"), &digest_1)?
                    .value()
                    .zip(expected_packed_digest.as_ref())
                    .assert_if_known(|(packed, expected)| packed == expected);

                // Test that packing a 256-bit sha256 digest into a field element strips the two
                // most significant bits of the last word's least significant byte.
                sha256_words_chip
                    .pack_digest(layouter.namespace(|| "pack digest_2"), &digest_2)?
                    .value()
                    .zip(expected_packed_digest.as_ref())
                    .assert_if_known(|(packed, expected)| packed == expected);

                Ok(())
            }
        }

        let circ = MyCircuit;
        let prover = MockProver::<Fp>::run(8, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
