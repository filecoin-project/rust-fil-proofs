#![allow(clippy::large_enum_variant)]
#![allow(clippy::unusual_byte_groupings)]

use std::convert::TryInto;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

use crate::{
    boolean::pack_bits,
    pack_ints,
    sha256::{
        compress::{
            values, AssignedU32, CompressChip, CompressConfig, InputBlock, Word, BLOCK_WORDS,
            FIELD_WORDS, STATE_WORDS, STRIP_MASK, U32,
        },
        get_padding_len,
    },
    AdviceIter, ColumnCount, MaybeAssigned, NumCols,
};

#[derive(Clone, Copy, PartialEq)]
pub enum IsPadded {
    Yes,
    No,
}

#[derive(Clone, Debug)]
pub struct CompressFieldConfig<F: FieldExt> {
    compress: CompressConfig<F, 16>,
    advice: Vec<Column<Advice>>,
    s_field_into_u32s: Selector,
    s_word_bits_into_u32: Selector,
    s_digest_words_into_u32s: Selector,
    s_strip_bits: Selector,
}

impl<F: FieldExt> CompressFieldConfig<F> {
    #[inline]
    fn field_into_u32s_cols(&self) -> (Column<Advice>, &[Column<Advice>]) {
        (self.advice[0], &self.advice[1..1 + FIELD_WORDS])
    }

    #[inline]
    fn digest_words_into_u32s_cols(
        &self,
        word_index_in_row: usize,
    ) -> (Column<Advice>, &[Column<Advice>], Column<Advice>) {
        // 6 columns per word-to-`u32` conversion: 1 column for word, 4 columns for word bytes, and
        // 1 column for reversed bytes' packing.
        let cols = self.advice.chunks_exact(6).nth(word_index_in_row).unwrap();
        (cols[0], &cols[1..5], cols[5])
    }

    #[inline]
    fn strip_bits_cols(&self) -> (Column<Advice>, &[Column<Advice>]) {
        (self.compress.int_col, &self.compress.bit_cols)
    }

    #[inline]
    fn strip_bits_int_col(&self) -> Column<Advice> {
        self.strip_bits_cols().0
    }
}

#[derive(Clone, Debug)]
pub struct CompressFieldChip<F: FieldExt> {
    config: CompressFieldConfig<F>,
}

impl<F: FieldExt> Chip<F> for CompressFieldChip<F> {
    type Config = CompressFieldConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ColumnCount for CompressFieldChip<F> {
    #[inline]
    fn num_cols() -> NumCols {
        CompressChip::<F, 16>::num_cols()
    }
}

impl<F: FieldExt> CompressFieldChip<F> {
    pub fn construct(config: CompressFieldConfig<F>) -> Self {
        CompressFieldChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: &[Column<Advice>],
        fixed: &Column<Fixed>,
    ) -> CompressFieldConfig<F> {
        let compress = CompressChip::configure(meta, advice, fixed);
        let advice = advice[..Self::num_cols().advice_eq].to_vec();

        let config = CompressFieldConfig {
            compress,
            advice,
            s_field_into_u32s: meta.selector(),
            s_word_bits_into_u32: meta.selector(),
            s_digest_words_into_u32s: meta.selector(),
            s_strip_bits: meta.selector(),
        };

        meta.create_gate("field_into_u32s", |meta| {
            let s = meta.query_selector(config.s_field_into_u32s);

            let (f_col, u32_cols) = config.field_into_u32s_cols();

            let f = meta.query_advice(f_col, Rotation::cur());
            let u32s = u32_cols
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .collect();
            let f_packed = pack_ints(u32s, 1 << 32);

            [s * (f - f_packed)]
        });

        meta.create_gate("word_bits_into_u32", |meta| {
            let s = meta.query_selector(config.s_word_bits_into_u32);

            let u32_ = meta.query_advice(config.compress.int_col, Rotation::next());

            let word_bits: Vec<Expression<F>> = AdviceIter::from(config.compress.bit_cols.to_vec())
                .take(32)
                .map(|(offset, col)| meta.query_advice(col, Rotation(offset as i32)))
                .collect();

            // Words and `u32`s have opposite byte order.
            let word_bytes = word_bits.chunks(8);
            let u32_bytes = word_bytes.rev();
            let u32_bits = u32_bytes.flatten().cloned().collect();
            let u32_packed = pack_bits(u32_bits);

            [s * (u32_ - u32_packed)]
        });

        meta.create_gate("strip_bits", |meta| {
            let s = meta.query_selector(config.s_strip_bits);

            let (int_col, bit_cols) = config.strip_bits_cols();

            let unstripped = meta.query_advice(int_col, Rotation::cur());
            let unstripped_bits: Vec<Expression<F>> = AdviceIter::from(bit_cols.to_vec())
                .take(32)
                .map(|(offset, col)| meta.query_advice(col, Rotation(offset as i32)))
                .collect();
            let unstripped_packed = pack_bits(unstripped_bits.clone());

            let stripped = meta.query_advice(int_col, Rotation::next());
            let stripped_bits = &unstripped_bits[..30];
            let stripped_packed = pack_bits(stripped_bits.to_vec());

            Constraints::with_selector(
                s,
                [
                    ("unstripped packing", unstripped - unstripped_packed),
                    ("stripped packing", stripped - stripped_packed),
                ],
            )
        });

        meta.create_gate("digest_words_into_u32s", |meta| {
            let s = meta.query_selector(config.s_digest_words_into_u32s);

            let words_per_row = Self::words_into_u32s_per_row();

            let byte_decomps: Vec<Expression<F>> = (0..words_per_row)
                .flat_map(|i| {
                    let (word_col, byte_cols, rev_col) = config.digest_words_into_u32s_cols(i);

                    let word = meta.query_advice(word_col, Rotation::cur());
                    let rev = meta.query_advice(rev_col, Rotation::cur());

                    let word_bytes: Vec<Expression<F>> = byte_cols
                        .iter()
                        .map(|col| meta.query_advice(*col, Rotation::cur()))
                        .collect();
                    let rev_bytes: Vec<Expression<F>> = word_bytes.iter().cloned().rev().collect();

                    let word_packed = pack_ints(word_bytes, 1 << 8);
                    let rev_packed = pack_ints(rev_bytes, 1 << 8);

                    [word - word_packed, rev - rev_packed]
                })
                .collect();

            Constraints::with_selector(s, byte_decomps)
        });

        config
    }

    fn field_into_u32s(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        offset: &mut usize,
        f: MaybeAssigned<F, F>,
    ) -> Result<[AssignedU32<F>; FIELD_WORDS], Error> {
        let annotation = format!("{} field_into_u32s", annotation);

        self.config.s_field_into_u32s.enable(region, *offset)?;

        let (f_col, u32_cols) = self.config.field_into_u32s_cols();

        let f = match f {
            MaybeAssigned::Unassigned(f) => {
                region.assign_advice(|| format!("{} f", annotation), f_col, *offset, || f)?
            }
            MaybeAssigned::Assigned(f) => {
                f.copy_advice(|| format!("{} copy f", annotation), region, f_col, *offset)?
            }
            _ => unimplemented!(),
        };

        let u32_values = values::f_to_u32s(&f.value().copied());

        let u32s = u32_values
            .iter()
            .zip(u32_cols)
            .enumerate()
            .map(|(i, (u32_, col))| {
                region.assign_advice(
                    || format!("{} u32_{}", annotation, i),
                    *col,
                    *offset,
                    || u32_.map(U32),
                )
            })
            .collect::<Result<Vec<AssignedU32<F>>, Error>>()
            .map(|u32s| u32s.try_into().unwrap())?;

        *offset += 1;
        Ok(u32s)
    }

    // Word decomposition must occur in the same region as `CompressChip::compress`.
    fn field_into_words(
        &self,
        region: &mut Region<'_, F>,
        annotation: &str,
        offset: &mut usize,
        f: MaybeAssigned<F, F>,
    ) -> Result<[Word<F>; FIELD_WORDS], Error> {
        let annotation = format!("{} field_into_words", annotation);
        let u32s = self.field_into_u32s(region, &annotation, offset, f)?;

        let annotation = format!("{} u32s_into_words", annotation);
        let compress_chip = CompressChip::construct(self.config.compress.clone());

        u32s.iter()
            .enumerate()
            .map(|(i, u32_)| {
                self.config.s_word_bits_into_u32.enable(region, *offset)?;
                let word = compress_chip.assign_word(
                    region,
                    &format!("{} word_{}", annotation, i),
                    offset,
                    &u32_.value().map(|u32_| u32::from(u32_).swap_bytes()),
                    true,
                )?;
                u32_.copy_advice(
                    || format!("{} copy u32_{}", annotation, i),
                    region,
                    self.config.compress.int_col,
                    word.offset + 1,
                )?;
                Ok(word)
            })
            .collect::<Result<Vec<Word<F>>, Error>>()
            .map(|words| words.try_into().unwrap())
    }

    // Reverses each digest word's byte-endianess, i.e. converts each word from word-endianess to
    // `u32`-endianess.
    fn digest_words_into_u32s(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        digest_words: &[Word<F>; STATE_WORDS],
    ) -> Result<[AssignedU32<F>; STATE_WORDS], Error> {
        let annotation = "digest_words_into_u32s";

        let mut digest_u32s = Vec::<AssignedU32<F>>::with_capacity(STATE_WORDS);
        let mut word_index = 0;
        let words_per_row = Self::words_into_u32s_per_row();

        for row_words in digest_words.chunks(words_per_row) {
            self.config
                .s_digest_words_into_u32s
                .enable(region, *offset)?;

            for (word_index_in_row, word) in row_words.iter().enumerate() {
                let (word_col, byte_cols, u32_col) =
                    self.config.digest_words_into_u32s_cols(word_index_in_row);

                let word = word.int.clone().unwrap();
                let word_value = word.value().map(u32::from);

                // Copy word to decompose.
                word.copy_advice(
                    || format!("{} copy word_{}", annotation, word_index),
                    region,
                    word_col,
                    *offset,
                )?;

                // Assign word's bytes.
                for (byte_index, (byte_value, byte_col)) in word_value
                    .map(u32::to_le_bytes)
                    .transpose_array()
                    .iter()
                    .zip(byte_cols)
                    .enumerate()
                {
                    region.assign_advice(
                        || format!("{} word_{} byte_{}", annotation, word_index, byte_index),
                        *byte_col,
                        *offset,
                        || byte_value.map(|byte| F::from(byte as u64)),
                    )?;
                }

                // Assign `u32`, i.e. word after byte reversal.
                let u32_ = region.assign_advice(
                    || format!("{} word_{} u32", annotation, word_index),
                    u32_col,
                    *offset,
                    || word_value.map(|word| U32(word.swap_bytes())),
                )?;
                digest_u32s.push(u32_);
                word_index += 1;
            }

            *offset += 1;
        }

        Ok(digest_u32s.try_into().unwrap())
    }

    fn strip_bits(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        u32_: &AssignedU32<F>,
    ) -> Result<AssignedU32<F>, Error> {
        let annotation = "strip_bits";

        self.config.s_strip_bits.enable(region, *offset)?;

        let compress_chip = CompressChip::construct(self.config.compress.clone());
        let unstripped_value = u32_.value().map(u32::from);
        let stripped_value = unstripped_value.map(|u32_| u32_ & STRIP_MASK);

        // Copy unstripped `u32` and assign its bits.
        let unstripped = compress_chip.assign_word(
            region,
            &format!("{} copy unstripped u32", annotation),
            offset,
            &unstripped_value,
            true,
        )?;
        let unstripped_cell = unstripped.int_unchecked().cell();
        region.constrain_equal(unstripped_cell, u32_.cell())?;

        // Strip two most significant bits from `u32`.
        region.assign_advice(
            || format!("{} stripped u32", annotation),
            self.config.strip_bits_int_col(),
            unstripped.offset + 1,
            || stripped_value.map(U32),
        )
    }

    fn digest_u32s_into_field(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        digest_u32s: &[AssignedU32<F>; STATE_WORDS],
    ) -> Result<AssignedCell<F, F>, Error> {
        let annotation = "digest_u32s_into_field";

        self.config.s_field_into_u32s.enable(region, *offset)?;

        let (f_col, u32_cols) = self.config.field_into_u32s_cols();

        for (i, (u32_, col)) in digest_u32s.iter().zip(u32_cols).enumerate() {
            u32_.copy_advice(
                || format!("{} copy u32_{}", annotation, i),
                region,
                *col,
                *offset,
            )?;
        }

        let u32_values = digest_u32s
            .iter()
            .map(|u32_| u32_.value().copied().map(u32::from))
            .collect::<Vec<Value<u32>>>()
            .try_into()
            .unwrap();

        let packed_digest = region.assign_advice(
            || format!("{} f", annotation),
            f_col,
            *offset,
            || values::u32s_to_f(&u32_values),
        )?;

        *offset += 1;
        Ok(packed_digest)
    }

    pub fn hash_field_elems(
        &self,
        mut layouter: impl Layouter<F>,
        preimage: &[MaybeAssigned<F, F>],
        is_padded: IsPadded,
    ) -> Result<AssignedCell<F, F>, Error> {
        let compress_chip = CompressChip::construct(self.config.compress.clone());

        layouter.assign_region(
            || "sha256 field elems",
            |mut region| {
                let mut offset = 0;

                let preimage_word_len = preimage.len() * FIELD_WORDS;

                let mut padding = if is_padded == IsPadded::Yes {
                    assert_eq!(preimage_word_len % BLOCK_WORDS, 0);
                    vec![]
                } else {
                    compress_chip.assign_padding(&mut region, &mut offset, preimage_word_len)?
                };

                let preimage_blocks: Vec<InputBlock<F>> = preimage
                    .iter()
                    .enumerate()
                    .map(|(i, f)| {
                        self.field_into_words(
                            &mut region,
                            &format!("preimage f_{}", i),
                            &mut offset,
                            f.clone(),
                        )
                    })
                    .collect::<Result<Vec<[Word<F>; FIELD_WORDS]>, Error>>()?
                    .drain(..)
                    .flatten()
                    .chain(padding.drain(..))
                    .collect::<Vec<Word<F>>>()
                    .chunks(BLOCK_WORDS)
                    .map(InputBlock::from)
                    .collect();

                let digest_words =
                    compress_chip.hash(&mut region, &mut offset, &preimage_blocks)?;

                // Change the byte-endianess of each digest word.
                let mut digest_u32s =
                    self.digest_words_into_u32s(&mut region, &mut offset, &digest_words)?;

                // Strip the two most significant bits from the digest's last `u32`.
                let last_u32 = digest_u32s.last_mut().unwrap();
                *last_u32 = self.strip_bits(&mut region, &mut offset, last_u32)?;

                self.digest_u32s_into_field(&mut region, &mut offset, &digest_u32s)
            },
        )
    }

    pub fn hash_unassigned_field_elems(
        &self,
        layouter: impl Layouter<F>,
        preimage: &[Value<F>],
        is_padded: IsPadded,
    ) -> Result<AssignedCell<F, F>, Error> {
        let preimage: Vec<MaybeAssigned<F, F>> =
            preimage.iter().copied().map(MaybeAssigned::from).collect();
        self.hash_field_elems(layouter, &preimage, is_padded)
    }

    #[inline]
    const fn words_into_u32s_per_row() -> usize {
        2
    }

    #[inline]
    const fn field_into_u32s_rows() -> usize {
        1
    }

    #[inline]
    const fn u32_into_word_rows() -> usize {
        CompressChip::<F, 16>::word_rows()
    }

    #[inline]
    const fn field_into_words_rows() -> usize {
        Self::field_into_u32s_rows() + FIELD_WORDS * Self::u32_into_word_rows()
    }

    #[inline]
    fn digest_words_into_u32s_rows() -> usize {
        STATE_WORDS / Self::words_into_u32s_per_row()
    }

    #[inline]
    const fn strip_bits_rows() -> usize {
        CompressChip::<F, 16>::word_rows()
    }

    #[inline]
    const fn digest_u32s_into_field_rows() -> usize {
        1
    }

    pub fn hash_field_elems_rows(unpadded_preimage_field_len: usize) -> usize {
        assert_ne!(unpadded_preimage_field_len, 0);

        let unpadded_preimage_word_len = unpadded_preimage_field_len * FIELD_WORDS;
        let padding_word_len = get_padding_len(unpadded_preimage_word_len);
        let padded_preimage_word_len = unpadded_preimage_word_len + padding_word_len;
        let num_blocks = padded_preimage_word_len / BLOCK_WORDS;

        let preimage_into_words_rows = unpadded_preimage_word_len * Self::field_into_words_rows();
        let assign_padding_rows = padding_word_len * CompressChip::<F, 16>::word_rows();
        let hash_rows = CompressChip::<F, 16>::hash_rows(num_blocks);

        preimage_into_words_rows
            + assign_padding_rows
            + hash_rows
            + Self::digest_words_into_u32s_rows()
            + Self::strip_bits_rows()
            + Self::digest_u32s_into_field_rows()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};

    use crate::{
        sha256::{
            compress::{f_to_u32s, f_to_words},
            get_padding,
        },
        CircuitSize, ColumnBuilder,
    };

    #[test]
    fn test_compress_field_chip() {
        // Configures the preimage length in field elements.
        const PREIMAGE_FIELD_LEN: usize = 1;

        type CompressFieldChip = super::CompressFieldChip<Fp>;
        type CompressFieldConfig = super::CompressFieldConfig<Fp>;
        type CompressChip = super::CompressChip<Fp, 16>;

        #[derive(Clone)]
        struct MyCircuit {
            preimage: Vec<Value<Fp>>,
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = CompressFieldConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    preimage: vec![Value::unknown(); self.preimage.len()],
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
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let compress_chip = CompressChip::construct(config.compress.clone());
                let chip = CompressFieldChip::construct(config);

                layouter.assign_region(
                    || "test assign_padding",
                    |mut region| {
                        let mut offset = 0;

                        let preimage_word_len = self.preimage.len() * FIELD_WORDS;

                        let padding = compress_chip.assign_padding(
                            &mut region,
                            &mut offset,
                            preimage_word_len,
                        )?;

                        let padding_expected = get_padding(preimage_word_len);
                        let padding_len = padding_expected.len();

                        assert_eq!(padding.len(), padding_len);
                        assert_eq!(offset, padding_len * CompressChip::word_rows());

                        for (word, expected) in padding.iter().zip(padding_expected) {
                            assert!(word.bits.iter().all(|bit| bit.is_some()));
                            assert!(word.int.is_some());
                            word.value_u32().assert_if_known(|word| *word == expected);
                        }

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test field_into_u32s",
                    |mut region| {
                        let mut offset = 0;

                        let f = Fp::zero() - Fp::one();

                        let u32s = chip.field_into_u32s(
                            &mut region,
                            "test",
                            &mut offset,
                            Value::known(f).into(),
                        )?;

                        assert_eq!(offset, CompressFieldChip::field_into_u32s_rows());

                        let u32s_expected = f_to_u32s(&f);

                        for (u32_, expected) in u32s.iter().zip(u32s_expected) {
                            u32_.value()
                                .assert_if_known(|u32_| u32::from(*u32_) == expected);
                        }

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test field_into_words",
                    |mut region| {
                        let mut offset = 0;

                        let f = Fp::zero() - Fp::one();

                        let words = chip.field_into_words(
                            &mut region,
                            "test",
                            &mut offset,
                            Value::known(f).into(),
                        )?;

                        assert_eq!(offset, CompressFieldChip::field_into_words_rows());

                        let words_expected = f_to_words(&f);

                        for (word, expected) in words.iter().zip(words_expected) {
                            assert!(word.bits.iter().all(|bit| bit.is_some()));
                            assert!(word.int.is_some());
                            word.value_u32().assert_if_known(|word| *word == expected);
                        }

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test digest_words_into_u32s",
                    |mut region| {
                        let mut offset = 0;

                        let words: [u32; STATE_WORDS] = [
                            0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666,
                            0x77777777, 0x88888888,
                        ];

                        let digest_words: [Word<Fp>; STATE_WORDS] = words
                            .iter()
                            .enumerate()
                            .map(|(i, word)| {
                                compress_chip.assign_word(
                                    &mut region,
                                    &format!("word_{}", i),
                                    &mut offset,
                                    &Value::known(*word),
                                    true,
                                )
                            })
                            .collect::<Result<Vec<Word<Fp>>, Error>>()
                            .map(|digest| digest.try_into().unwrap())?;

                        let offset_before = offset;

                        let digest_u32s =
                            chip.digest_words_into_u32s(&mut region, &mut offset, &digest_words)?;

                        assert_eq!(
                            offset - offset_before,
                            CompressFieldChip::digest_words_into_u32s_rows(),
                        );

                        let u32s_expected: Vec<u32> =
                            words.iter().copied().map(u32::swap_bytes).collect();

                        for (u32_, expected) in digest_u32s.iter().zip(&u32s_expected) {
                            u32_.value()
                                .assert_if_known(|u32_| u32::from(*u32_) == *expected);
                        }

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test strip_bits",
                    |mut region| {
                        let mut offset = 0;

                        let u32_ = 0xff00abcd;

                        let unstripped = region.assign_advice(
                            || "u32",
                            chip.config.advice[0],
                            offset,
                            || Value::known(U32(u32_)),
                        )?;
                        offset += 1;

                        let offset_before = offset;

                        let stripped = chip.strip_bits(&mut region, &mut offset, &unstripped)?;

                        assert_eq!(offset - offset_before, CompressFieldChip::strip_bits_rows());

                        stripped.value().assert_if_known(|stripped| {
                            u32::from(*stripped) == (u32_ & STRIP_MASK)
                        });

                        Ok(())
                    },
                )?;

                layouter.assign_region(
                    || "test digest_u32s_into_field",
                    |mut region| {
                        let mut offset = 0;

                        let neg_1 = Fp::zero() - Fp::one();

                        let u32s: [AssignedU32<Fp>; STATE_WORDS] = f_to_u32s(&neg_1)
                            .iter()
                            .zip(&chip.config.advice)
                            .enumerate()
                            .map(|(i, (u32_, col))| {
                                region.assign_advice(
                                    || format!("u32_{}", i),
                                    *col,
                                    offset,
                                    || Value::known(U32(*u32_)),
                                )
                            })
                            .collect::<Result<Vec<AssignedU32<Fp>>, Error>>()
                            .map(|digest| digest.try_into().unwrap())?;

                        offset += 1;
                        let offset_before = offset;

                        let f = chip.digest_u32s_into_field(&mut region, &mut offset, &u32s)?;

                        assert_eq!(
                            offset - offset_before,
                            CompressFieldChip::digest_u32s_into_field_rows(),
                        );

                        f.value().assert_if_known(|f| **f == neg_1);

                        Ok(())
                    },
                )?;

                let digest =
                    chip.hash_unassigned_field_elems(layouter, &self.preimage, IsPadded::No)?;

                let digest_expected = values::hash_field_elems_unpadded(&self.preimage);

                digest
                    .value()
                    .zip(digest_expected.as_ref())
                    .assert_if_known(|(digest, expected)| digest == expected);

                Ok(())
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                let word_rows = CompressChip::word_rows();

                let unpadded_preimage_field_len = self.preimage.len();
                let unpadded_preimage_word_len = unpadded_preimage_field_len * FIELD_WORDS;
                let padding_word_len = get_padding_len(unpadded_preimage_word_len);

                let assign_padding_rows = padding_word_len * word_rows;
                let field_into_u32s_rows = CompressFieldChip::field_into_u32s_rows();
                let field_into_words_rows = CompressFieldChip::field_into_words_rows();
                let digest_words_into_u32s_rows =
                    STATE_WORDS * word_rows + CompressFieldChip::digest_words_into_u32s_rows();
                let strip_bits_rows = CompressFieldChip::strip_bits_rows() + 1;
                let digest_u32s_into_field_rows =
                    CompressFieldChip::digest_u32s_into_field_rows() + 1;
                let hash_rows =
                    CompressFieldChip::hash_field_elems_rows(unpadded_preimage_field_len);

                assign_padding_rows
                    + field_into_u32s_rows
                    + field_into_words_rows
                    + digest_words_into_u32s_rows
                    + strip_bits_rows
                    + digest_u32s_into_field_rows
                    + hash_rows
            }
        }

        let circ = MyCircuit {
            preimage: (0..PREIMAGE_FIELD_LEN as u64)
                .map(|i| Value::known(Fp::from(i)))
                .collect(),
        };

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
