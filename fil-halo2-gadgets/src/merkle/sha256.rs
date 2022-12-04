use std::convert::TryInto;
use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

use crate::{
    boolean::{AssignedBit, Bit},
    convert_assigned_f,
    sha256::compress::{self, AssignedU32, InputBlock, Word, BLOCK_WORDS, STATE_WORDS, U32},
    utilities::pick,
    ColumnBuilder, ColumnCount, MaybeAssigned, NumCols,
};

const HALF_STATE_WORDS: usize = STATE_WORDS / 2;

#[derive(Clone, Debug)]
pub struct InsertConfig<F: FieldExt> {
    bit_col: Column<Advice>,
    digest_0_cols: [Column<Advice>; HALF_STATE_WORDS],
    digest_1_cols: [Column<Advice>; HALF_STATE_WORDS],
    inserted_lo_cols: [Column<Advice>; HALF_STATE_WORDS],
    inserted_hi_cols: [Column<Advice>; HALF_STATE_WORDS],
    s_insert: Selector,
    _f: PhantomData<F>,
}

#[derive(Clone)]
pub struct InsertChip<F: FieldExt> {
    config: InsertConfig<F>,
}

impl<F: FieldExt> ColumnCount for InsertChip<F> {
    fn num_cols() -> NumCols {
        NumCols {
            advice_eq: 4 * HALF_STATE_WORDS + 1,
            ..Default::default()
        }
    }
}

impl<F: FieldExt> InsertChip<F> {
    pub fn construct(config: InsertConfig<F>) -> Self {
        InsertChip { config }
    }

    // # Side Effects
    //
    // The first `Self::num_cols().advice_eq` advice columns will be equality enabled.
    #[allow(clippy::unwrap_used)]
    pub fn configure(meta: &mut ConstraintSystem<F>, advice: &[Column<Advice>]) -> InsertConfig<F> {
        let num_advice = Self::num_cols().advice_eq;
        assert!(advice.len() >= num_advice);

        let advice = &advice[..num_advice];

        for col in advice {
            meta.enable_equality(*col);
        }

        let mut advice = advice.iter().copied();
        let bit_col = advice.next().unwrap();
        let digest_0_cols: Vec<Column<Advice>> = (&mut advice).take(HALF_STATE_WORDS).collect();
        let digest_1_cols: Vec<Column<Advice>> = (&mut advice).take(HALF_STATE_WORDS).collect();
        let inserted_lo_cols: Vec<Column<Advice>> = (&mut advice).take(HALF_STATE_WORDS).collect();
        let inserted_hi_cols: Vec<Column<Advice>> = (&mut advice).take(HALF_STATE_WORDS).collect();

        let s_insert = meta.selector();
        meta.create_gate("insert_sha256_digest", |meta| {
            let s = meta.query_selector(s_insert);

            let bit = meta.query_advice(bit_col, Rotation::cur());

            let mut choices_lo = Vec::<Expression<F>>::with_capacity(HALF_STATE_WORDS);
            let mut choices_hi = Vec::<Expression<F>>::with_capacity(HALF_STATE_WORDS);

            for (((word_0_col, word_1_col), inserted_lo_col), inserted_hi_col) in digest_0_cols
                .iter()
                .zip(&digest_1_cols)
                .zip(&inserted_lo_cols)
                .zip(&inserted_hi_cols)
            {
                let word_0 = meta.query_advice(*word_0_col, Rotation::cur());
                let word_1 = meta.query_advice(*word_1_col, Rotation::cur());

                let inserted_lo = meta.query_advice(*inserted_lo_col, Rotation::cur());
                let inserted_hi = meta.query_advice(*inserted_hi_col, Rotation::cur());

                let choice_lo = pick(bit.clone(), word_0.clone(), word_1.clone());
                let choice_hi = pick(bit.clone(), word_1, word_0);

                choices_lo.push(inserted_lo - choice_lo);
                choices_hi.push(inserted_hi - choice_hi);
            }
            let mut choices_lo = choices_lo.drain(..);
            let mut choices_hi = choices_hi.drain(..);

            Constraints::with_selector(
                s,
                [
                    ("pick lo_0", choices_lo.next().unwrap()),
                    ("pick lo_1", choices_lo.next().unwrap()),
                    ("pick lo_2", choices_lo.next().unwrap()),
                    ("pick lo_3", choices_lo.next().unwrap()),
                    ("pick hi_0", choices_hi.next().unwrap()),
                    ("pick hi_1", choices_hi.next().unwrap()),
                    ("pick hi_2", choices_hi.next().unwrap()),
                    ("pick hi_3", choices_hi.next().unwrap()),
                ],
            )
        });

        InsertConfig {
            bit_col,
            digest_0_cols: digest_0_cols.try_into().unwrap(),
            digest_1_cols: digest_1_cols.try_into().unwrap(),
            inserted_lo_cols: inserted_lo_cols.try_into().unwrap(),
            inserted_hi_cols: inserted_hi_cols.try_into().unwrap(),
            s_insert,
            _f: PhantomData,
        }
    }

    pub fn insert(
        &self,
        mut layouter: impl Layouter<F>,
        digest_0: &Value<[u32; STATE_WORDS]>,
        digest_1: &[MaybeAssigned<U32, F>; STATE_WORDS],
        bit: &MaybeAssigned<Bit, F>,
    ) -> Result<[AssignedU32<F>; BLOCK_WORDS], Error> {
        layouter.assign_region(
            || "insert_sha256_digest",
            |mut region| {
                let mut digest_word_index = 0;
                let mut inserted_lo = Vec::<AssignedU32<F>>::with_capacity(HALF_STATE_WORDS);
                let mut inserted_hi = Vec::<AssignedU32<F>>::with_capacity(HALF_STATE_WORDS);

                for offset in 0..2 {
                    self.config.s_insert.enable(&mut region, offset)?;

                    let bit: AssignedBit<F> = match bit {
                        MaybeAssigned::Unassigned(ref bit) => {
                            region.assign_advice(|| "bit", self.config.bit_col, offset, || *bit)?
                        }
                        MaybeAssigned::Assigned(ref bit) => bit.copy_advice(
                            || "copy bit",
                            &mut region,
                            self.config.bit_col,
                            offset,
                        )?,
                        MaybeAssigned::Pi(pi_col, pi_row) => region
                            .assign_advice_from_instance(
                                || "copy pi bit",
                                *pi_col,
                                *pi_row,
                                self.config.bit_col,
                                offset,
                            )
                            .map(convert_assigned_f)?,
                    };

                    // Assign half of `digest_0`, assign or copy half of `digest_1`, and assign half of
                    // the inserted array (as one low and one high quarter).
                    for i in 0..HALF_STATE_WORDS {
                        let word_0 = region.assign_advice(
                            || format!("digest_0_word_{}", digest_word_index),
                            self.config.digest_0_cols[i],
                            offset,
                            || digest_0.map(|words| U32(words[digest_word_index])),
                        )?;

                        let word_1 = match digest_1[digest_word_index] {
                            MaybeAssigned::Unassigned(word) => region.assign_advice(
                                || format!("digest_1_word_{}", digest_word_index),
                                self.config.digest_1_cols[i],
                                offset,
                                || word,
                            )?,
                            MaybeAssigned::Assigned(ref word) => word.copy_advice(
                                || format!("copy digest_1_word_{}", digest_word_index),
                                &mut region,
                                self.config.digest_1_cols[i],
                                offset,
                            )?,
                            _ => unreachable!(),
                        };

                        let (inserted_lo_value, inserted_hi_value) = bit
                            .value()
                            .zip(word_0.value())
                            .zip(word_1.value())
                            .map(|((bit, &word_0), &word_1)| {
                                if bool::from(bit) {
                                    (word_0, word_1)
                                } else {
                                    (word_1, word_0)
                                }
                            })
                            .unzip();

                        let mut inserted_word_index = digest_word_index;
                        region
                            .assign_advice(
                                || format!("inserted_word_{}", inserted_word_index),
                                self.config.inserted_lo_cols[i],
                                offset,
                                || inserted_lo_value,
                            )
                            .map(|word| inserted_lo.push(word))?;

                        inserted_word_index += HALF_STATE_WORDS;
                        region
                            .assign_advice(
                                || format!("inserted_word_{}", inserted_word_index),
                                self.config.inserted_hi_cols[i],
                                offset,
                                || inserted_hi_value,
                            )
                            .map(|word| inserted_hi.push(word))?;

                        digest_word_index += 1;
                    }
                }

                // Join low and high halves of the inserted array.
                let inserted = inserted_lo
                    .drain(..)
                    .chain(inserted_hi.drain(..))
                    .collect::<Vec<AssignedU32<F>>>()
                    .try_into()
                    .unwrap();

                Ok(inserted)
            },
        )
    }

    pub fn insert_unassigned(
        &self,
        layouter: impl Layouter<F>,
        digest_0: &Value<[u32; STATE_WORDS]>,
        digest_1: &Value<[u32; STATE_WORDS]>,
        bit: &MaybeAssigned<Bit, F>,
    ) -> Result<[AssignedU32<F>; BLOCK_WORDS], Error> {
        let digest_1 = digest_1
            .transpose_array()
            .iter()
            .map(|word| word.map(U32).into())
            .collect::<Vec<MaybeAssigned<U32, F>>>()
            .try_into()
            .unwrap();
        self.insert(layouter, digest_0, &digest_1, bit)
    }

    pub fn insert_assigned(
        &self,
        layouter: impl Layouter<F>,
        digest_0: &Value<[u32; STATE_WORDS]>,
        digest_1: &[AssignedU32<F>; STATE_WORDS],
        bit: &MaybeAssigned<Bit, F>,
    ) -> Result<[AssignedU32<F>; BLOCK_WORDS], Error> {
        let digest_1 = digest_1
            .iter()
            .map(|word| word.clone().into())
            .collect::<Vec<MaybeAssigned<U32, F>>>()
            .try_into()
            .unwrap();
        self.insert(layouter, digest_0, &digest_1, bit)
    }

    #[inline]
    pub const fn num_rows() -> usize {
        2
    }
}

// Each Merkle hash function's preimage block length; the first block is the concatenation of two
// sha256 digests and the second block is sha256 padding.
const PREIMAGE_BLOCKS: usize = 2;

// Each Merkle hash function's preimage word length.
const PREIMAGE_WORDS: usize = PREIMAGE_BLOCKS * BLOCK_WORDS;

type CompressChip<F> = compress::CompressChip<F, 16>;
type CompressConfig<F> = compress::CompressConfig<F, 16>;

#[derive(Clone, Debug)]
pub struct Sha256MerkleConfig<F: FieldExt> {
    compress: CompressConfig<F>,
    insert: InsertConfig<F>,
}

#[derive(Clone)]
pub struct Sha256MerkleChip<F: FieldExt> {
    config: Sha256MerkleConfig<F>,
}

impl<F: FieldExt> ColumnCount for Sha256MerkleChip<F> {
    fn num_cols() -> NumCols {
        ColumnBuilder::new()
            .with_chip::<InsertChip<F>>()
            .with_chip::<CompressChip<F>>()
            .num_cols()
    }
}

impl<F: FieldExt> Sha256MerkleChip<F> {
    pub fn construct(config: Sha256MerkleConfig<F>) -> Self {
        Sha256MerkleChip { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: &[Column<Advice>],
        fixed: &Column<Fixed>,
    ) -> Sha256MerkleConfig<F> {
        Sha256MerkleConfig {
            insert: InsertChip::configure(meta, advice),
            compress: CompressChip::configure(meta, advice, fixed),
        }
    }

    fn hash(
        &self,
        layouter: &mut impl Layouter<F>,
        unpadded_preimage: &[AssignedU32<F>; BLOCK_WORDS],
        height: &mut usize,
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        let compress_chip = CompressChip::construct(self.config.compress.clone());

        let digest = layouter.assign_region(
            || format!("compress (height = {})", height),
            |mut region| {
                let mut offset = 0;

                // Copy preimage words, assign each's 32 bits, and assign sha256 padding.
                let mut padded_preimage = Vec::<Word<F>>::with_capacity(PREIMAGE_WORDS);

                for (i, word_int) in unpadded_preimage.iter().enumerate() {
                    let word = compress_chip.assign_word(
                        &mut region,
                        &format!("preimage copy word_{}", i),
                        &mut offset,
                        &word_int.value().map(u32::from),
                        true,
                    )?;
                    region.constrain_equal(word.int_unchecked().cell(), word_int.cell())?;
                    padded_preimage.push(word);
                }

                let padding =
                    compress_chip.assign_padding(&mut region, &mut offset, BLOCK_WORDS)?;
                padded_preimage.extend(padding);

                let blocks = [
                    InputBlock::from(&padded_preimage[..BLOCK_WORDS]),
                    InputBlock::from(&padded_preimage[BLOCK_WORDS..]),
                ];

                compress_chip.hash(&mut region, &mut offset, &blocks)
            },
        )?;

        *height += 1;
        Ok(digest)
    }

    pub fn compute_root(
        &self,
        mut layouter: impl Layouter<F>,
        challenge_bits: &[MaybeAssigned<Bit, F>],
        leaf: [MaybeAssigned<U32, F>; STATE_WORDS],
        path: &[Value<[u32; STATE_WORDS]>],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        let path_len = path.len();
        assert_ne!(path_len, 0);
        assert_eq!(path_len, challenge_bits.len());

        let insert_chip = InsertChip::construct(self.config.insert.clone());

        let mut height = 0;
        let mut path = path.iter();
        let mut bits = challenge_bits.iter();

        let preimage = insert_chip.insert(
            layouter.namespace(|| format!("insert (height = {})", height)),
            path.next().unwrap(),
            &leaf,
            bits.next().unwrap(),
        )?;
        let mut cur = self.hash(&mut layouter, &preimage, &mut height)?;

        for (sib, bit) in path.zip(bits) {
            let cur_: [AssignedU32<F>; STATE_WORDS] = cur
                .iter()
                .map(|word| word.int_unchecked().clone())
                .collect::<Vec<AssignedU32<F>>>()
                .try_into()
                .unwrap();
            let preimage = insert_chip.insert_assigned(
                layouter.namespace(|| format!("insert (height = {})", height)),
                sib,
                &cur_,
                bit,
            )?;
            cur = self.hash(&mut layouter, &preimage, &mut height)?;
        }

        Ok(cur)
    }

    pub fn compute_root_unassigned_leaf(
        &self,
        layouter: impl Layouter<F>,
        challenge_bits: &[MaybeAssigned<Bit, F>],
        leaf: &Value<[u32; STATE_WORDS]>,
        path: &[Value<[u32; STATE_WORDS]>],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        let leaf = leaf
            .transpose_array()
            .iter()
            .map(|word| word.map(U32).into())
            .collect::<Vec<MaybeAssigned<U32, F>>>()
            .try_into()
            .unwrap();
        self.compute_root(layouter, challenge_bits, leaf, path)
    }

    pub fn compute_root_assigned_leaf(
        &self,
        layouter: impl Layouter<F>,
        challenge_bits: &[MaybeAssigned<Bit, F>],
        leaf: &[AssignedU32<F>; STATE_WORDS],
        path: &[Value<[u32; STATE_WORDS]>],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        let leaf = leaf
            .iter()
            .map(|word| word.clone().into())
            .collect::<Vec<MaybeAssigned<U32, F>>>()
            .try_into()
            .unwrap();
        self.compute_root(layouter, challenge_bits, leaf, path)
    }

    pub fn compute_root_unassigned(
        &self,
        layouter: impl Layouter<F>,
        challenge_bits: &[Value<bool>],
        leaf: &Value<[u32; STATE_WORDS]>,
        path: &[Value<[u32; STATE_WORDS]>],
    ) -> Result<[Word<F>; STATE_WORDS], Error> {
        let challenge_bits: Vec<MaybeAssigned<Bit, F>> = challenge_bits
            .iter()
            .map(|bit| bit.map(Bit).into())
            .collect();

        let leaf = leaf
            .transpose_array()
            .iter()
            .map(|word| word.map(U32).into())
            .collect::<Vec<MaybeAssigned<U32, F>>>()
            .try_into()
            .unwrap();

        self.compute_root(layouter, &challenge_bits, leaf, path)
    }

    pub fn num_rows(path_len: usize) -> usize {
        let insert_rows = InsertChip::<F>::num_rows();
        let compress_rows = CompressChip::<F>::hash_rows(PREIMAGE_BLOCKS);
        path_len * (insert_rows + compress_rows)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, pasta::Fp, plonk::Circuit};
    use sha2::{Digest, Sha256};

    use crate::{sha256::compress::WORD_BYTES, CircuitSize};

    #[test]
    fn test_insert_sha256_digest_chip() {
        type InsertChip = super::InsertChip<Fp>;
        type InsertConfig = super::InsertConfig<Fp>;

        #[derive(Clone)]
        struct MyCircuit;

        impl Circuit<Fp> for MyCircuit {
            type Config = InsertConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let (advice, _, _, _) = ColumnBuilder::new()
                    .with_chip::<InsertChip>()
                    .create_columns(meta);
                InsertChip::configure(meta, &advice)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let chip = InsertChip::construct(config);

                let digest_0_values =
                    Value::known([0x11u32, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

                let digest_1_values = [
                    Value::known(0x99),
                    Value::known(0x00),
                    Value::known(0xaa),
                    Value::known(0xbb),
                    Value::known(0xcc),
                    Value::known(0xdd),
                    Value::known(0xee),
                    Value::known(0xff),
                ];

                let digest_1 = digest_1_values
                    .iter()
                    .map(|word| word.map(U32).into())
                    .collect::<Vec<MaybeAssigned<U32, Fp>>>()
                    .try_into()
                    .unwrap();

                let inserted_first = chip.insert(
                    layouter.namespace(|| "insert_first"),
                    &digest_0_values,
                    &digest_1,
                    &Value::known(Bit(false)).into(),
                )?;

                let inserted_second = chip.insert(
                    layouter.namespace(|| "insert_second"),
                    &digest_0_values,
                    &digest_1,
                    &Value::known(Bit(true)).into(),
                )?;

                let digest_0_values = digest_0_values.transpose_vec(STATE_WORDS);
                let inserted_first_expected = digest_1_values.iter().chain(&digest_0_values);
                let inserted_second_expected = digest_0_values.iter().chain(&digest_1_values);

                for (word, expected) in inserted_first.iter().zip(inserted_first_expected) {
                    word.value()
                        .zip(*expected)
                        .assert_if_known(|(word, expected)| u32::from(*word) == *expected);
                }

                for (word, expected) in inserted_second.iter().zip(inserted_second_expected) {
                    word.value()
                        .zip(*expected)
                        .assert_if_known(|(word, expected)| u32::from(*word) == *expected);
                }

                Ok(())
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                2 * InsertChip::num_rows()
            }
        }

        let circ = MyCircuit;
        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }

    #[test]
    fn test_sha256_merkle_chip() {
        // Configures Merkle tree height.
        const HEIGHT: usize = 2;

        const NUM_LEAFS: usize = 1 << HEIGHT;
        const CHALLENGE: usize = NUM_LEAFS >> 1;
        const BLOCK_BYTES: usize = BLOCK_WORDS * WORD_BYTES;

        type Sha256MerkleChip = super::Sha256MerkleChip<Fp>;
        type Sha256MerkleConfig = super::Sha256MerkleConfig<Fp>;

        #[derive(Clone)]
        struct MyCircuit {
            leaf: Value<[u32; STATE_WORDS]>,
            path: Vec<Value<[u32; STATE_WORDS]>>,
            challenge_bits: Vec<Value<bool>>,
            root: Value<[u32; STATE_WORDS]>,
        }

        impl Circuit<Fp> for MyCircuit {
            type Config = Sha256MerkleConfig;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                MyCircuit {
                    leaf: Value::unknown(),
                    path: vec![Value::unknown(); self.path.len()],
                    challenge_bits: vec![Value::unknown(); self.challenge_bits.len()],
                    root: Value::unknown(),
                }
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let (advice, _, fixed, _) = ColumnBuilder::new()
                    .with_chip::<Sha256MerkleChip>()
                    .create_columns(meta);
                Sha256MerkleChip::configure(meta, &advice, &fixed[0])
            }

            fn synthesize(
                &self,
                config: Self::Config,
                layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let chip = Sha256MerkleChip::construct(config);

                let root = chip.compute_root_unassigned(
                    layouter,
                    &self.challenge_bits,
                    &self.leaf,
                    &self.path,
                )?;

                for (word, expected) in root.iter().zip(&self.root.transpose_array()) {
                    word.value_u32()
                        .zip(*expected)
                        .assert_if_known(|(word, expected)| word == expected);
                }

                Ok(())
            }
        }

        impl CircuitSize<Fp> for MyCircuit {
            fn num_rows(&self) -> usize {
                Sha256MerkleChip::num_rows(self.path.len())
            }
        }

        let leafs: Vec<[u32; STATE_WORDS]> =
            (0..NUM_LEAFS).map(|i| [i as u32; STATE_WORDS]).collect();

        let mut tree: Vec<Vec<[u32; STATE_WORDS]>> = Vec::with_capacity(HEIGHT + 1);
        tree.push(leafs);
        for _ in 0..HEIGHT {
            let prev_layer = tree.last().unwrap();
            let layer: Vec<[u32; STATE_WORDS]> = prev_layer
                .chunks(2)
                .map(|pair| {
                    let mut unpadded_preimage_bytes = Vec::<u8>::with_capacity(BLOCK_BYTES);
                    for words in pair {
                        for word in words {
                            unpadded_preimage_bytes.extend(word.to_be_bytes());
                        }
                    }
                    let digest_bytes = Sha256::digest(&unpadded_preimage_bytes);
                    digest_bytes
                        .chunks(WORD_BYTES)
                        .map(|word_bytes| u32::from_be_bytes(word_bytes.try_into().unwrap()))
                        .collect::<Vec<u32>>()
                        .try_into()
                        .unwrap()
                })
                .collect();
            tree.push(layer);
        }

        let leaf = tree[0][CHALLENGE];
        let root = tree.last().unwrap()[0];
        let path = (0..HEIGHT)
            .map(|height| {
                let cur_index_in_layer = CHALLENGE >> height;
                let sib_index_in_layer = cur_index_in_layer ^ 1;
                Value::known(tree[height][sib_index_in_layer])
            })
            .collect();
        let challenge_bits = (0..HEIGHT)
            .map(|i| Value::known(CHALLENGE >> i & 1 == 1))
            .collect();

        let circ = MyCircuit {
            leaf: Value::known(leaf),
            path,
            challenge_bits,
            root: Value::known(root),
        };

        let prover = MockProver::<Fp>::run(circ.k(), &circ, vec![]).unwrap();
        assert!(prover.verify().is_ok());
    }
}
