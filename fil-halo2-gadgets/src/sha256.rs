//! Gadget and chips for the [SHA-256] hash function.
//!
//! [SHA-256]: https://tools.ietf.org/html/rfc6234

use std::cmp::min;
use std::convert::TryInto;
use std::fmt;
use std::iter;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use crate::{
    boolean::AssignedBits,
    uint32::{self, U32DecompChip, U32DecompConfig, StripBitsChip, StripBitsConfig},
    AdviceIter,
};

// Don't reformat code copied from `halo2_gadgets` repo.
#[rustfmt::skip]
mod table16;

pub use table16::{BlockWord, Table16Chip, Table16Config};

use table16::{
    CompressionConfig, MessageScheduleConfig, SpreadTableChip, SpreadTableConfig, State, IV,
};

/// The size of a SHA-256 block, in 32-bit words.
pub const BLOCK_SIZE: usize = 16;
/// The size of a SHA-256 digest, in 32-bit words.
pub const DIGEST_SIZE: usize = 8;

// Each field element is eight 32-bit words.
const FIELD_WORDS: usize = 8;

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

#[derive(Clone, Debug)]
pub struct Sha256Config<F: FieldExt> {
    lookup: SpreadTableConfig,
    message_schedule: MessageScheduleConfig<F>,
    compression: CompressionConfig<F>,
    // Set to `None` if Sha256 is used to hash 32-bit words exclusively, otherwise set to `Some` if
    // Sha256 is used to hash 256-bit field elements.
    packing: Option<(U32DecompConfig<F>, StripBitsConfig<F>)>,
    // Columns that are equality enabled and not used for lookup inputs, i.e. `a_3, ..., a_8`. These
    // columns can be used to assign padding.
    advice: [Column<Advice>; 6],
}

#[derive(Debug)]
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

impl<F: FieldExt> Sha256Chip<F> {
    pub fn construct(config: Sha256Config<F>) -> Self {
        Sha256Chip { config }
    }

    /// Loads the lookup table required by this chip into the circuit.
    pub fn load(layouter: &mut impl Layouter<F>, config: &Sha256Config<F>) -> Result<(), Error> {
        SpreadTableChip::load(config.lookup.clone(), layouter)
    }

    pub fn configure_with_packing(
        meta: &mut ConstraintSystem<F>,
        u32_decomp: U32DecompConfig<F>,
        strip_bits: StripBitsConfig<F>,
    ) -> Sha256Config<F> {
        let advice = u32_decomp.limbs[..6].try_into().unwrap();
        let extra = u32_decomp.limbs[6];
        let mut config = Self::configure_without_packing(meta, advice, extra);
        config.packing = Some((u32_decomp, strip_bits));
        config
    }

    pub fn configure_without_packing(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 6],
        extra: Column<Advice>,
    ) -> Sha256Config<F> {
        // Lookup table inputs cannot be repurposed by the caller; create those columns here and store
        // them privately.
        let input_tag = meta.advice_column();
        let input_dense = meta.advice_column();
        let input_spread = meta.advice_column();

        // Rename these here for ease of matching the gates to the specification.
        let _a_0 = input_tag;
        let a_1 = input_dense;
        let a_2 = input_spread;
        let [a_3, a_4, a_5, a_6, a_7, a_8] = advice;
        let a_9 = extra;

        // Add all advice columns to permutation
        for col in [a_1, a_2, a_3, a_4, a_5, a_6, a_7, a_8].iter() {
            meta.enable_equality(*col);
        }

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

        Sha256Config {
            lookup,
            message_schedule,
            compression,
            packing: None,
            advice,
        }
    }

    /// Assign the padding for an assigned, but not yet padded, preimage.
    fn assign_padding(
        &self,
        layouter: &mut impl Layouter<F>,
        preimage: &[AssignedBits<F, 32>],
    ) -> Result<Vec<AssignedBits<F, 32>>, Error> {
        layouter.assign_region(
            || "padding",
            |mut region| {
                let words_utilized = preimage.len();
                let bits_utilized = 32 * words_utilized;

                // The padding scheme requires that there are at least 3 unutilized words in the
                // preimage's last block: one word to append a `1` bit onto the end of the preimage
                // (i.e. append the word `2u32^31`) and two words to encode the number of preimage
                // bits (note: the number of preimage bits is a `u64`, thus requires two 32-bit
                // words to encode). If there is less than 3 unutilized words in the preimage's last
                // block, add a full block of padding.
                let mut pad_words = BLOCK_SIZE - (words_utilized % BLOCK_SIZE);
                if pad_words < 3 {
                    pad_words += BLOCK_SIZE;
                }
                let num_zeros = pad_words - 3;

                let mut padding_iter = iter::once(1 << 31)
                    .chain(iter::repeat(0).take(num_zeros))
                    .chain(iter::once((bits_utilized >> 32) as u32))
                    .chain(iter::once((bits_utilized & 0xffffffff) as u32));

                let padding_rows = {
                    let cols = self.config.advice.len();
                    let mut rows = pad_words / cols;
                    if pad_words % cols > 0 {
                        rows += 1;
                    };
                    rows
                };

                let mut padding = Vec::<AssignedBits<F, 32>>::with_capacity(pad_words);
                let mut word_index = 0;

                'outer: for row in 0..padding_rows {
                    for col in self.config.advice.iter() {
                        match padding_iter.next() {
                            Some(word) => {
                                let word = AssignedBits::<F, 32>::assign(
                                    &mut region,
                                    || format!("padding {}", word_index),
                                    *col,
                                    row,
                                    Some(word),
                                )?;
                                padding.push(word);
                                word_index += 1;
                            }
                            None => break 'outer,
                        };
                    }
                }

                Ok(padding)
            },
        )
    }

    fn initialization_vector(&self, layouter: &mut impl Layouter<F>) -> Result<State<F>, Error> {
        self.config.compression.initialize_with_iv(layouter, IV)
    }

    fn initialization(
        &self,
        layouter: &mut impl Layouter<F>,
        init_state: State<F>,
    ) -> Result<State<F>, Error> {
        self.config
            .compression
            .initialize_with_state(layouter, init_state)
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

    fn assign_digest(
        &self,
        layouter: &mut impl Layouter<F>,
        state: State<F>,
    ) -> Result<[AssignedBits<F, 32>; DIGEST_SIZE], Error> {
        self.config.compression.digest(layouter, state)
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

        let mut blocks = preimage.chunks(BLOCK_SIZE);

        // Process the first block.
        let mut state = self.initialization_vector(&mut layouter)?;
        state = self.compress(
            &mut layouter,
            state.clone(),
            blocks.next().unwrap().to_vec().try_into().unwrap(),
        )?;

        // Process any additional blocks.
        for block in blocks {
            state = self.initialization(&mut layouter, state.clone())?;
            state = self.compress(
                &mut layouter,
                state.clone(),
                block.to_vec().try_into().unwrap(),
            )?;
        }

        self.assign_digest(&mut layouter, state)
    }

    /// Hash `preimage`; `preimage` must must be assigned in columns which are equality enabled.
    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        preimage: &[AssignedBits<F, 32>],
    ) -> Result<[AssignedBits<F, 32>; DIGEST_SIZE], Error> {
        let mut padding = self.assign_padding(&mut layouter, preimage)?;
        let padded_preimage: Vec<AssignedBits<F, 32>> =
            preimage.iter().cloned().chain(padding.drain(..)).collect();
        self.hash_nopad(layouter, &padded_preimage)
    }

    pub fn hash_field_elems(
        &self,
        mut layouter: impl Layouter<F>,
        preimage: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        assert!(
            self.config.packing.is_some(),
            "sha256 chip is not configured to hash field elements",
        );
        let (u32_decomp_config, strip_bits_config) = self.config.packing.clone().unwrap();
        let u32_decomp_chip = U32DecompChip::construct(u32_decomp_config);
        let strip_bits_chip = StripBitsChip::construct(strip_bits_config);

        // Decompose each preimage element into eight 32-bit words.
        let mut preimage_words =
            Vec::<AssignedBits<F, 32>>::with_capacity(FIELD_WORDS * preimage.len());
        for (i, elem) in preimage.iter().enumerate() {
            let words = u32_decomp_chip.copy_decompose(
                layouter.namespace(|| format!("preimage elem {} into u32s", i)),
                elem.clone(),
            )?;
            preimage_words.extend(words);
        }

        // Pad the preimage words and hash.
        let mut digest_words = self.hash(layouter.namespace(|| "hash"), &preimage_words)?;

        // Ensure that the packed digest is a valid field element by stripping its two most
        // significant bits.
        digest_words[7] =
            strip_bits_chip.strip_bits(layouter.namespace(|| "strip bits"), &digest_words[7])?;

        // Pack the digest words into a field element.
        u32_decomp_chip.pack(layouter.namespace(|| "pack digest"), &digest_words)
    }
}

#[derive(Clone, Debug)]
pub struct Sha256PackedConfig<F: FieldExt> {
    lookup: SpreadTableConfig,
    message_schedule: MessageScheduleConfig<F>,
    compression: CompressionConfig<F>,
    // Equality enabled advice.
    advice: [Column<Advice>; uint32::NUM_ADVICE_EQ],
    s_u32_decomp: Selector,
    strip_bits: StripBitsConfig<F>,
}

#[derive(Debug)]
pub struct Sha256PackedChip<F: FieldExt> {
    config: Sha256PackedConfig<F>,
}

impl<F: FieldExt> Chip<F> for Sha256PackedChip<F> {
    type Config = Sha256PackedConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> Sha256PackedChip<F> {
    pub fn construct(config: Sha256PackedConfig<F>) -> Self {
        Sha256PackedChip { config }
    }

    /// Loads the lookup table required by this chip into the circuit.
    pub fn load(layouter: &mut impl Layouter<F>, config: &Sha256PackedConfig<F>) -> Result<(), Error> {
        SpreadTableChip::load(config.lookup.clone(), layouter)
    }

    // # Side Effects
    //
    // `advice[..uint32::NUM_ADVICE_EQ]` will be equality constrained.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: &[Column<Advice>],
    ) -> Sha256PackedConfig<F> {
        assert!(advice.len() >= uint32::NUM_ADVICE_EQ);
        let advice: [Column<Advice>; uint32::NUM_ADVICE_EQ] =
            advice[..uint32::NUM_ADVICE_EQ].try_into().unwrap();

        // Lookup table input columns cannot be repurposed by the caller; create those columns here
        // and store privately.
        let input_tag = meta.advice_column();
        let input_dense = meta.advice_column();
        let input_spread = meta.advice_column();

        // Add all advice columns to permutation
        for col in [input_tag, input_dense, input_spread].iter().chain(advice.iter()) {
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

        let s_u32_decomp = meta.selector();

        // `[2^32, (2^32)^2, .., (2^32)^7]`
        let mut powers_of_u32_radix = Vec::with_capacity(7);
        let radix = F::from(1 << 32);
        powers_of_u32_radix.push(radix);
        for i in 0..6 {
            powers_of_u32_radix.push(powers_of_u32_radix[i] * radix);
        }

        meta.create_gate("field_into_u32s", |meta| {
            let s = meta.query_selector(s_u32_decomp);
            let value = meta.query_advice(advice[0], Rotation::cur());
            let mut expr = meta.query_advice(advice[1], Rotation::cur());
            for (col, radix_pow) in advice[2..].iter().zip(powers_of_u32_radix.iter()) {
                let limb = meta.query_advice(*col, Rotation::cur());
                expr = expr + Expression::Constant(*radix_pow) * limb;
            }
            vec![s * (expr - value)]
        });

        let strip_bits = StripBitsChip::configure(meta, advice);

        Sha256PackedConfig {
            lookup,
            message_schedule,
            compression,
            advice,
            s_u32_decomp,
            strip_bits,
        }
    }

    /// Pad and assign the preimage as 32-bit words.
    fn assign_preimage(
        &self,
        layouter: &mut impl Layouter<F>,
        preimage: &[AssignedCell<F, F>],
    ) -> Result<Vec<AssignedBits<F, 32>>, Error> {
        let preimage_len = preimage.len();
        let preimage_words = 8 * preimage_len;
        let preimage_bits = 256 * preimage_len;

        // The padding scheme requires that there are at least 3 unutilized words (or one
        // field element) in the preimage's last block; one word to append a `1` bit onto
        // the end of the preimage (i.e. the word `2^31`) and two words to encode the
        // preimage length in bits. If there is less than 3 unutilized words in the
        // preimage's last block (i.e. one field element), add padding until the end of the
        // next block.
        let last_block_words_used = preimage_words % BLOCK_SIZE;
        let last_block_words_rem = BLOCK_SIZE - last_block_words_used;
        let num_pad_words = if last_block_words_rem >= 1 {
            last_block_words_rem
        } else {
            last_block_words_rem + BLOCK_SIZE
        };

        let mut padding = vec![0u32; num_pad_words];
        padding[0] = 1 << 31;
        padding[num_pad_words - 2] = (preimage_bits >> 32) as u32;
        padding[num_pad_words - 1] = (preimage_bits & 0xffffffff) as u32;

        layouter.assign_region(
            || "assign padded preimage",
            |mut region| {
                let mut offset = 0;

                let mut padded_preimage = Vec::<AssignedBits<F, 32>>::with_capacity(
                    preimage_words + num_pad_words,
                );

                // Copy and decompose each preimage element.
                for (i, elem) in preimage.iter().enumerate() {
                    self.config.s_u32_decomp.enable(&mut region, offset)?;

                    let elem = elem.copy_advice(
                        || format!("preimage elem {}", i),
                        &mut region,
                        self.config.advice[0],
                        offset,
                    )?;

                    let repr = elem.value().map(|elem| elem.to_repr().as_ref().to_vec());

                    for (j, col) in self.config.advice[1..].iter().enumerate() {
                        let word = repr.as_ref().map(|repr| {
                            u32::from_le_bytes(repr[j * 4..(j + 1) * 4].try_into().unwrap())
                        });
                        let word = AssignedBits::<F, 32>::assign(
                            &mut region,
                            || format!("preimage elem {}, word {}", i, j),
                            *col,
                            offset,
                            word,
                        )?;
                        padded_preimage.push(word);
                    }

                    offset += 1;
                }

                let mut advice_iter = AdviceIter::new(offset, self.config.advice.to_vec());

                // Assign padding.
                for (i, pad_word) in padding.iter().enumerate() {
                    let (offset, col) = advice_iter.next().unwrap();
                    let pad_word = AssignedBits::<F, 32>::assign(
                        &mut region,
                        || format!("padding word {}", i),
                        col,
                        offset,
                        Some(*pad_word),
                    )?;
                    padded_preimage.push(pad_word);
                }

                Ok(padded_preimage)
            },
        )
    }

    fn initialization_vector(&self, layouter: &mut impl Layouter<F>) -> Result<State<F>, Error> {
        self.config.compression.initialize_with_iv(layouter, IV)
    }

    fn initialization(
        &self,
        layouter: &mut impl Layouter<F>,
        init_state: State<F>,
    ) -> Result<State<F>, Error> {
        self.config
            .compression
            .initialize_with_state(layouter, init_state)
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

    fn assign_digest(
        &self,
        layouter: &mut impl Layouter<F>,
        state: State<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut digest_words = self.config.compression.digest(layouter, state)?;

        // Ensure that the packed digest is a valid field element by stripping its two most
        // significant bits.
        digest_words[7] = StripBitsChip::construct(self.config.strip_bits.clone())
            .strip_bits(layouter.namespace(|| "strip digest bits"), &digest_words[7])?;

        // Pack digest into a field element.
        let mut packed_digest_repr = Some(F::Repr::default());
        for (i, word) in digest_words.iter().enumerate() {
            let word_bytes = word.value_u32().map(|word| word.to_le_bytes());
            packed_digest_repr = packed_digest_repr.zip(word_bytes).map(|(mut repr, word_bytes)| {
                repr.as_mut()[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
                repr
            });
        }

        let packed_digest = packed_digest_repr.map(|repr| {
            F::from_repr_vartime(repr).expect("packed digest is invalid field element")
        });

        layouter.assign_region(
            || "pack digest",
            |mut region| {
                let offset = 0;
                self.config.s_u32_decomp.enable(&mut region, offset)?;
                let packed_digest = region.assign_advice(
                    || "packed digest",
                    self.config.advice[0],
                    offset,
                    || packed_digest.ok_or(Error::Synthesis),
                )?;
                for (i, (word, col)) in
                    digest_words.iter().zip(self.config.advice[1..].iter()).enumerate()
                {
                    word.copy_advice(
                        || format!("copy digest word {}", i),
                        &mut region,
                        *col,
                        offset,
                    )?;
                }
                Ok(packed_digest)
            },
        )
    }

    pub fn hash_field_elems(
        &self,
        mut layouter: impl Layouter<F>,
        preimage: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        let padded_preimage = self.assign_preimage(&mut layouter, preimage)?;

        assert_eq!(
            padded_preimage.len() % BLOCK_SIZE,
            0,
            "padded preimage length is not divisible by block size",
        );

        let mut blocks = padded_preimage.chunks(BLOCK_SIZE);

        // Process the first block.
        let mut state = self.initialization_vector(&mut layouter)?;
        state = self.compress(
            &mut layouter,
            state.clone(),
            blocks.next().unwrap().to_vec().try_into().unwrap(),
        )?;

        // Process any additional blocks.
        for block in blocks {
            state = self.initialization(&mut layouter, state.clone())?;
            state = self.compress(
                &mut layouter,
                state.clone(),
                block.to_vec().try_into().unwrap(),
            )?;
        }

        // Compute digest.
        self.assign_digest(&mut layouter, state)
    }
}

// TODO: fix failing tests.
/*
#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use sha2::{Digest, Sha256};

    use crate::{
        uint32::{U32DecompChip, U32DecompConfig},
        TEST_SEED,
    };

    const PREIMAGE_LEN: usize = 2;

    #[test]
    fn test_sha256_arity_2_circuit() {
        #[derive(Clone)]
        struct MyConfig<F: FieldExt> {
            u32_decomp: U32DecompConfig<F>,
            sha256: Sha256Config<F>,
        }

        struct MyCircuit<F: FieldExt> {
            preimage: [Option<F>; PREIMAGE_LEN],
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    preimage: [None; PREIMAGE_LEN],
                }
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let advice: Vec<Column<Advice>> = (0..9).map(|_| meta.advice_column()).collect();

                // Enables equality for all `advice` columns.
                let u32_decomp = U32DecompChip::configure(meta, advice.clone().try_into().unwrap());

                let sha256 = Sha256Chip::configure_without_packing(
                    meta,
                    advice[..6].try_into().unwrap(),
                    advice[6],
                );

                MyConfig { u32_decomp, sha256 }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let MyConfig {
                    u32_decomp: u32_decomp_config,
                    sha256: sha256_config,
                } = config;

                Sha256Chip::load(&mut layouter, &sha256_config)?;

                let u32_decomp_chip = U32DecompChip::construct(u32_decomp_config);
                let sha256_chip = Sha256Chip::construct(sha256_config);

                let mut preimage =
                    Vec::<AssignedBits<F, 32>>::with_capacity(FIELD_WORDS * PREIMAGE_LEN);

                for (i, elem) in self.preimage.iter().enumerate() {
                    let u32s = u32_decomp_chip
                        .witness_decompose(layouter.namespace(|| format!("elem {}", i)), *elem)?;
                    preimage.extend(u32s);
                }

                let digest: Vec<u32> = sha256_chip
                    .hash(layouter.namespace(|| "sha256"), &preimage)?
                    .iter()
                    .map(|word| word.value_u32().unwrap())
                    .collect();

                let expected_digest: Vec<u32> = {
                    let mut preimage = Vec::<u8>::with_capacity(32 * PREIMAGE_LEN);
                    for elem in self.preimage {
                        preimage.extend_from_slice(elem.unwrap().to_repr().as_ref());
                    }
                    Sha256::digest(&preimage)
                        .chunks(4)
                        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
                        .collect()
                };

                // TODO: fix this failing test
                dbg!(&digest);
                dbg!(&expected_digest);
                assert_eq!(digest, expected_digest);

                Ok(())
            }
        }

        impl<F: FieldExt> MyCircuit<F> {
            fn k() -> u32 {
                17
            }
        }

        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        let preimage = (0..PREIMAGE_LEN)
            .map(|_| Some(Fp::random(&mut rng)))
            .collect::<Vec<Option<Fp>>>()
            .try_into()
            .unwrap();

        let circ = MyCircuit { preimage };

        let k = MyCircuit::<Fp>::k();
        let prover = MockProver::run(k, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_sha256_two_preimages_circuit() {
        struct MyCircuit<F: FieldExt> {
            preimage_1: [Option<F>; PREIMAGE_LEN],
            preimage_2: [Option<F>; PREIMAGE_LEN],
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = Sha256Config<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    preimage_1: [None; PREIMAGE_LEN],
                    preimage_2: [None; PREIMAGE_LEN],
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
                    meta.advice_column(),
                ];
                let u32_decomp = U32DecompChip::configure(meta, advice);
                let strip_bits = StripBitsChip::configure(meta, advice);
                Sha256Chip::configure_with_packing(meta, u32_decomp, strip_bits)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                Sha256Chip::load(&mut layouter, &config)?;

                let advice = config.advice;
                let sha256_chip = Sha256Chip::construct(config);

                let (preimage_1, preimage_2) = layouter.assign_region(
                    || "assign preimages",
                    |mut region| {
                        let mut offset = 0;

                        let preimage_1 = self
                            .preimage_1
                            .iter()
                            .enumerate()
                            .map(|(i, elem)| {
                                region.assign_advice(
                                    || format!("preimage 1 elem {}", i),
                                    advice[i],
                                    offset,
                                    || elem.ok_or(Error::Synthesis),
                                )
                            })
                            .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()?;

                        offset += 1;

                        let preimage_2 = self
                            .preimage_2
                            .iter()
                            .enumerate()
                            .map(|(i, elem)| {
                                region.assign_advice(
                                    || format!("preimage 2 elem {}", i),
                                    advice[i],
                                    offset,
                                    || elem.ok_or(Error::Synthesis),
                                )
                            })
                            .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()?;

                        Ok((preimage_1, preimage_2))
                    },
                )?;

                let _digest_1 =
                    sha256_chip.hash_field_elems(layouter.namespace(|| "hash 1"), &preimage_1)?;

                let _digest_2 =
                    sha256_chip.hash_field_elems(layouter.namespace(|| "hash 2"), &preimage_2)?;

                Ok(())
            }
        }

        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        let preimage_1 = (0..PREIMAGE_LEN)
            .map(|_| Some(Fp::random(&mut rng)))
            .collect::<Vec<Option<Fp>>>()
            .try_into()
            .unwrap();

        let preimage_2 = (0..PREIMAGE_LEN)
            .map(|_| Some(Fp::random(&mut rng)))
            .collect::<Vec<Option<Fp>>>()
            .try_into()
            .unwrap();

        let circ = MyCircuit {
            preimage_1,
            preimage_2,
        };

        let prover = MockProver::run(17, &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
*/
