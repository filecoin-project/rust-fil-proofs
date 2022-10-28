use std::convert::TryInto;
use std::ops::Range;

use fil_halo2_gadgets::{
    boolean::AssignedBits,
    sha256::get_padding,
    sha256_compress::{
        sha256_block_values_padded, sha256_word_values_padded, BLOCK_WORDS, PAD_WORDS, STATE_WORDS,
    },
    AdviceIter, CircuitSize, ColumnBuilder,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::{CircuitCost, MockProver},
    pasta::{Eq, Fp},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
};

// Configures the range of preimage sizes to measure `k` for.
const PREIMAGE_BLOCK_SIZES: Range<usize> = 1..20;

type Sha256Chip = fil_halo2_gadgets::sha256::Sha256Chip<Fp>;
type Sha256Config = fil_halo2_gadgets::sha256::Sha256Config<Fp>;

// Configures the number of columns used by `CompressChip`.
const BIT_COLS: usize = 16;

type CompressChip = fil_halo2_gadgets::sha256_compress::CompressChip<Fp, BIT_COLS>;
type CompressConfig = fil_halo2_gadgets::sha256_compress::CompressConfig<Fp, BIT_COLS>;

fn sha256_chip_compute_k() {
    #[derive(Clone)]
    struct MyConfig {
        sha256: Sha256Config,
        advice: [Column<Advice>; 8],
    }

    struct MyCircuit {
        preimage: Vec<Value<u32>>,
        expected_digest: [Value<u32>; STATE_WORDS],
    }

    impl Circuit<Fp> for MyCircuit {
        type Config = MyConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit {
                preimage: vec![Value::unknown(); self.preimage.len()],
                expected_digest: [Value::unknown(); STATE_WORDS],
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let advice = ColumnBuilder::new()
                .with_chip::<Sha256Chip>()
                .create_columns(meta)
                .0
                .try_into()
                .unwrap();
            let sha256 = Sha256Chip::configure(meta, advice);
            MyConfig { sha256, advice }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
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
                            AssignedBits::<Fp, 32>::assign(
                                &mut region,
                                || format!("preimage word {}", i),
                                col,
                                offset,
                                *word,
                            )
                        })
                        .collect::<Result<Vec<AssignedBits<Fp, 32>>, Error>>()
                },
            )?;

            let digest = sha256_chip.hash_nopad(layouter.namespace(|| "sha256"), &preimage)?;

            for (word, word_expected) in digest.iter().zip(&self.expected_digest) {
                word.value_u32()
                    .zip(word_expected.as_ref())
                    .assert_if_known(|(word, word_expected)| word == *word_expected);
            }

            Ok(())
        }
    }

    println!("Sha256Chip:");

    let mut k = 1;
    for num_blocks in PREIMAGE_BLOCK_SIZES {
        let unpadded_preimage_word_len = num_blocks * BLOCK_WORDS - PAD_WORDS;

        let padded_preimage_words: Vec<Value<u32>> = (0..unpadded_preimage_word_len as u32)
            .chain(get_padding(unpadded_preimage_word_len))
            .map(Value::known)
            .collect();

        let expected_digest = sha256_word_values_padded(&padded_preimage_words);

        let circ = MyCircuit {
            preimage: padded_preimage_words,
            expected_digest,
        };

        loop {
            match MockProver::<Fp>::run(k, &circ, vec![]) {
                Ok(_) => {
                    // Proof size does not change with circuit size.
                    if num_blocks == PREIMAGE_BLOCK_SIZES.start {
                        let cost = CircuitCost::<Eq, MyCircuit>::measure(k as usize, &circ);
                        let proof_size: usize = cost.marginal_proof_size().into();
                        println!("\tproof_size = {} bytes", proof_size);
                    }
                    println!("\tblocks = {}: k = {}", num_blocks, k);
                    break;
                }
                Err(Error::NotEnoughRowsAvailable { .. }) | Err(Error::InstanceTooLarge) => k += 1,
                err => panic!("Unexpected error: {:?}", err),
            };
        }
    }
}

fn compress_chip_compute_k() {
    #[derive(Clone)]
    struct MyCircuit {
        blocks: Vec<[Value<u32>; BLOCK_WORDS]>,
        expected_digest: [Value<u32>; STATE_WORDS],
    }

    impl Circuit<Fp> for MyCircuit {
        type Config = CompressConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit {
                blocks: vec![[Value::unknown(); BLOCK_WORDS]; self.blocks.len()],
                expected_digest: [Value::unknown(); STATE_WORDS],
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

            for (word, word_expected) in digest.iter().zip(self.expected_digest) {
                word.value_u32()
                    .zip(word_expected)
                    .assert_if_known(|(word, word_expected)| word == word_expected);
            }

            Ok(())
        }
    }

    impl CircuitSize<Fp> for MyCircuit {
        fn num_rows(&self) -> usize {
            CompressChip::hash_rows(self.blocks.len())
        }
    }

    println!("CompressChip (BIT_COLS = {}):", BIT_COLS);

    let mut k = 1;
    for num_blocks in PREIMAGE_BLOCK_SIZES {
        let unpadded_preimage_word_len = num_blocks * BLOCK_WORDS - PAD_WORDS;

        let padded_preimage_blocks: Vec<[Value<u32>; BLOCK_WORDS]> = (0
            ..unpadded_preimage_word_len as u32)
            .chain(get_padding(unpadded_preimage_word_len))
            .collect::<Vec<u32>>()
            .chunks(BLOCK_WORDS)
            .map(|block| Value::known(block.try_into().unwrap()).transpose_array())
            .collect();

        let expected_digest = sha256_block_values_padded(&padded_preimage_blocks);

        let circ = MyCircuit {
            blocks: padded_preimage_blocks,
            expected_digest,
        };

        loop {
            match MockProver::<Fp>::run(k, &circ, vec![]) {
                Ok(_) => {
                    // Proof size does not change with circuit size.
                    if num_blocks == PREIMAGE_BLOCK_SIZES.start {
                        let cost = CircuitCost::<Eq, MyCircuit>::measure(k as usize, &circ);
                        let proof_size: usize = cost.marginal_proof_size().into();
                        println!("\tproof_size = {} bytes", proof_size);
                    }
                    println!(
                        "\tblocks = {}: k = {}, k_expected = {}",
                        num_blocks,
                        k,
                        circ.k()
                    );
                    break;
                }
                Err(Error::NotEnoughRowsAvailable { .. }) | Err(Error::InstanceTooLarge) => k += 1,
                err => panic!("Unexpected error: {:?}", err),
            };
        }
    }
}

fn main() {
    sha256_chip_compute_k();
    compress_chip_compute_k();
}
