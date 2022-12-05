use ff::PrimeFieldBits;
use fil_halo2_gadgets::boolean::Bit;
use halo2_gadgets::utilities::bool_check;
use halo2_gadgets::utilities::decompose_running_sum::RunningSumConfig;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Constraints, Error, Expression, Selector, SingleVerifier, VirtualCells,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::iter;
use std::ops::{BitAnd, BitXor, Not, Shr};

const SHA256_HASH_LENGTH_BITS: usize = 256;

#[allow(clippy::unreadable_literal)]
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[allow(clippy::unreadable_literal)]
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn u32_from_bits_be(bits: &[bool]) -> u32 {
    assert_eq!(bits.len(), 32);

    let mut u32_word = 0u32;
    for bit in bits {
        u32_word <<= 1;
        if *bit {
            u32_word |= 1;
        }
    }
    u32_word
}

fn u32_from_bits_le(bits: &[bool]) -> u32 {
    assert_eq!(bits.len(), 32);

    let mut u32_word = 0u32;
    for bit in bits.iter().rev() {
        u32_word <<= 1;
        if *bit {
            u32_word |= 1;
        }
    }
    u32_word
}

fn sha256_process_single_block(block: &[bool], cur_hash: [u32; 8]) -> [u32; 8] {
    assert_eq!(block.len(), 512);

    let mut w = vec![0u32; 64];
    for index in 0..16 {
        w[index] = u32_from_bits_be(&block[index * 32..index * 32 + 32])
    }

    for index in 16..64 {
        let s0 = w[index - 15]
            .rotate_right(7)
            .bitxor(w[index - 15].rotate_right(18))
            .bitxor(w[index - 15].shr(3));
        //println!("s0 expected: {}", s0);

        let s1 = w[index - 2]
            .rotate_right(17)
            .bitxor(w[index - 2].rotate_right(19))
            .bitxor(w[index - 2].shr(10));

        //println!("s1 expected: {}", s1);

        w[index] = w[index - 16] + s0 + w[index - 7] + s1;

        //println!("w[{}]: {}", index, w[index]);
    }

    let mut a = cur_hash[0];
    let mut b = cur_hash[1];
    let mut c = cur_hash[2];
    let mut d = cur_hash[3];
    let mut e = cur_hash[4];
    let mut f = cur_hash[5];
    let mut g = cur_hash[6];
    let mut h = cur_hash[7];

    for index in 0..64 {
        let s1 = e
            .rotate_right(6)
            .bitxor(e.rotate_right(11))
            .bitxor(e.rotate_right(25));

        let ch = e.bitand(f).bitxor(e.not().bitand(g));

        // temp1

        let s0 = a
            .rotate_right(2)
            .bitxor(a.rotate_right(13))
            .bitxor(a.rotate_right(22));

        let maj = a.bitand(b).bitxor(a.bitand(c)).bitxor(b.bitand(c));

        // temp2
        let tmp1 = h + s1 + ch + ROUND_CONSTANTS[index] + w[index];

        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + s0 + maj;
    }

    let h0 = cur_hash[0] + a;
    let h1 = cur_hash[1] + b;
    let h2 = cur_hash[2] + c;
    let h3 = cur_hash[3] + d;
    let h4 = cur_hash[4] + e;
    let h5 = cur_hash[5] + f;
    let h6 = cur_hash[6] + g;
    let h7 = cur_hash[7] + h;

    [h0, h1, h2, h3, h4, h5, h6, h7]
}

fn sha256_hashing(message: Vec<u8>) -> [u8; SHA256_HASH_LENGTH_BITS / 8] {
    assert_eq!(8 * message.len() % 512, 0);

    /*
     Pre-processing (Padding):
        begin with the original message of length L bits
        append a single '1' bit
        append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
        append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
        such that the bits in the message are: <original message of length L> 1 <K zeros> <L as 64 bit integer> , (the number of bits will be a multiple of 512)
    */

    let message_bits = bellperson::gadgets::multipack::bytes_to_bits(message.as_slice())
        .into_iter()
        .collect::<Vec<bool>>();

    let l = message.len() * 8;
    let mut k = 0;
    while (l + 1 + k + 64) % 512 != 0 {
        k += 1
    }

    let k_zeroes = vec![false; k];

    let l_bits =
        bellperson::gadgets::multipack::bytes_to_bits((l as u64).to_be_bytes().to_vec().as_slice())
            .into_iter()
            .collect::<Vec<bool>>();

    let padded_message = [message_bits, vec![true; 1], k_zeroes, l_bits].concat();

    // Processing
    let mut curr_hash = IV;
    for chunk in padded_message.chunks(512) {
        curr_hash = sha256_process_single_block(chunk, curr_hash);
    }

    let result = IntoIterator::into_iter(curr_hash)
        .flat_map(|word| word.to_be_bytes().to_vec())
        .collect::<Vec<u8>>();

    // we know definitely that result is actually a 8 32-bit words
    result.try_into().unwrap()
}

#[test]
fn test_self_made_sha256() {
    let message = vec![255u8; 128];

    let mut sha256 = Sha256::new();
    sha256.update(message.clone());
    let expected_hash: Vec<u8> = sha256.finalize().to_vec();

    let actual_hash = sha256_hashing(message);

    assert_eq!(expected_hash, actual_hash.to_vec());
}

#[derive(Clone, Debug)]
struct AssignedWord {
    bits: Vec<Option<AssignedCell<Bit, Fp>>>,
}

impl AssignedWord {
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
            .collect::<Vec<Option<AssignedCell<Bit, Fp>>>>();
        AssignedWord { bits }
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
            .collect::<Vec<Option<AssignedCell<Bit, Fp>>>>();
        AssignedWord { bits }
    }

    pub fn value_u32(&self) -> Value<u32> {
        self.bits
            .iter()
            .filter(|bit| bit.is_some())
            .enumerate()
            .fold(Value::known(0), |acc, (i, bit)| {
                acc + bit
                    .as_ref()
                    .unwrap()
                    .value()
                    .map(|bit| (bool::from(bit) as u32) << i)
            })
    }

    pub fn value_fp(&self) -> Value<Fp> {
        let value_u32 = self.value_u32();
        value_u32.map(|x| Fp::from(x as u64))
    }
}

const WORD_BIT_LEN: usize = 32;

#[derive(Clone)]
struct Sha256Config {
    // for loading words
    word: [Column<Advice>; 8],
    s_word: Selector,

    // for packing
    fp: Option<Column<Advice>>,
    bits: Option<[Column<Advice>; 8]>,
    s_pack: Option<Selector>,
}

struct Sha256Chip {
    config: Sha256Config,
}

impl Sha256Chip {
    fn construct(config: Sha256Config) -> Self {
        Sha256Chip { config }
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        word: [Column<Advice>; 8],
        s_word: Selector,
        fp: Option<Column<Advice>>,
        bits: Option<[Column<Advice>; 8]>,
        s_pack: Option<Selector>,
    ) -> Sha256Config {
        meta.create_gate("boolean constraint", |meta: &mut VirtualCells<Fp>| {
            let s_word = meta.query_selector(s_word);

            let mut bits_to_constraint = (0..WORD_BIT_LEN / word.len())
                .into_iter()
                .flat_map(|rotation_value| {
                    (0..word.len())
                        .into_iter()
                        .map(|index| {
                            meta.query_advice(word[index], Rotation(rotation_value as i32))
                        })
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>()
                .into_iter();

            Constraints::with_selector(
                s_word,
                [
                    ("0", bool_check(bits_to_constraint.next().unwrap())),
                    ("1", bool_check(bits_to_constraint.next().unwrap())),
                    ("2", bool_check(bits_to_constraint.next().unwrap())),
                    ("3", bool_check(bits_to_constraint.next().unwrap())),
                    ("4", bool_check(bits_to_constraint.next().unwrap())),
                    ("5", bool_check(bits_to_constraint.next().unwrap())),
                    ("6", bool_check(bits_to_constraint.next().unwrap())),
                    ("7", bool_check(bits_to_constraint.next().unwrap())),
                    ("8", bool_check(bits_to_constraint.next().unwrap())),
                    ("9", bool_check(bits_to_constraint.next().unwrap())),
                    ("10", bool_check(bits_to_constraint.next().unwrap())),
                    ("11", bool_check(bits_to_constraint.next().unwrap())),
                    ("12", bool_check(bits_to_constraint.next().unwrap())),
                    ("13", bool_check(bits_to_constraint.next().unwrap())),
                    ("14", bool_check(bits_to_constraint.next().unwrap())),
                    ("15", bool_check(bits_to_constraint.next().unwrap())),
                    ("16", bool_check(bits_to_constraint.next().unwrap())),
                    ("17", bool_check(bits_to_constraint.next().unwrap())),
                    ("18", bool_check(bits_to_constraint.next().unwrap())),
                    ("19", bool_check(bits_to_constraint.next().unwrap())),
                    ("20", bool_check(bits_to_constraint.next().unwrap())),
                    ("21", bool_check(bits_to_constraint.next().unwrap())),
                    ("22", bool_check(bits_to_constraint.next().unwrap())),
                    ("23", bool_check(bits_to_constraint.next().unwrap())),
                    ("24", bool_check(bits_to_constraint.next().unwrap())),
                    ("25", bool_check(bits_to_constraint.next().unwrap())),
                    ("26", bool_check(bits_to_constraint.next().unwrap())),
                    ("27", bool_check(bits_to_constraint.next().unwrap())),
                    ("28", bool_check(bits_to_constraint.next().unwrap())),
                    ("29", bool_check(bits_to_constraint.next().unwrap())),
                    ("30", bool_check(bits_to_constraint.next().unwrap())),
                    ("31", bool_check(bits_to_constraint.next().unwrap())),
                ],
            )
        });

        match s_pack {
            Some(s_pack) => {
                assert!(bits.is_some());
                assert!(fp.is_some());

                meta.create_gate("pack", |meta| {
                    let selector = meta.query_selector(s_pack);

                    let bits_columns = bits.unwrap();
                    let bits = (0..4)
                        .flat_map(|rot| {
                            (0..8)
                                .map(|index| meta.query_advice(bits_columns[index], Rotation(rot)))
                                .collect::<Vec<Expression<Fp>>>()
                        })
                        .collect::<Vec<Expression<Fp>>>();

                    let constant_expressions = (0..32)
                        .map(|degree_of_two| {
                            Expression::Constant(Fp::from(2_u64.pow(degree_of_two) as u64))
                        })
                        .collect::<Vec<Expression<Fp>>>();

                    let fp = meta.query_advice(fp.unwrap(), Rotation::cur());

                    let composed = bits
                        .iter()
                        .zip(&constant_expressions)
                        .fold(Expression::Constant(Fp::zero()), {
                            |acc, (bit, c)| acc + bit.clone() * c.clone()
                        });

                    Constraints::with_selector(selector, vec![("pack", composed - fp)])
                });
            }
            None => {}
        };

        Sha256Config {
            word,
            s_word,
            fp,
            bits,
            s_pack,
        }
    }

    fn load_word(
        &self,
        mut layouter: impl Layouter<Fp>,
        word: Option<[bool; WORD_BIT_LEN]>,
    ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
        layouter.assign_region(
            || "load word",
            |mut region| {
                self.config.s_word.enable(&mut region, 0)?;

                let word_columns = self.config.word.len();

                let assigned_word = match word {
                    Some(word) => word
                        .chunks(word_columns)
                        .into_iter()
                        .enumerate()
                        .flat_map(|(offset, word)| {
                            word.iter()
                                .enumerate()
                                .map(|(index, bit)| {
                                    region
                                        .assign_advice(
                                            || format!("bit {}", offset * word_columns + index),
                                            self.config.word[index],
                                            offset,
                                            || Value::known(Bit::from(*bit)),
                                        )
                                        .unwrap()
                                })
                                .collect::<Vec<AssignedCell<Bit, Fp>>>()
                        })
                        .collect::<Vec<AssignedCell<Bit, Fp>>>(),
                    None => (0..4)
                        .flat_map(|offset| {
                            (0..8)
                                .map(|index| {
                                    region
                                        .assign_advice(
                                            || format!("offset: {}, bit {}", offset, index),
                                            self.config.word[index],
                                            offset,
                                            || Value::unknown(),
                                        )
                                        .unwrap()
                                })
                                .collect::<Vec<AssignedCell<Bit, Fp>>>()
                        })
                        .collect::<Vec<AssignedCell<Bit, Fp>>>(),
                };

                Ok(assigned_word.try_into().unwrap())
            },
        )
    }

    fn pack_word(
        &self,
        mut layouter: impl Layouter<Fp>,
        word: AssignedWord,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        assert!(self.config.s_pack.is_some());
        assert!(self.config.fp.is_some());
        assert!(self.config.bits.is_some());
        layouter.assign_region(
            || "pack",
            |mut region| {
                self.config.s_pack.unwrap().enable(&mut region, 0)?;

                let bits_columns = self.config.bits.unwrap();
                for (offset, word) in word.bits.chunks(8).into_iter().enumerate() {
                    for (index, bit) in word.iter().enumerate() {
                        let bit = bit.as_ref();
                        if bit.is_some() {
                            bit.unwrap().copy_advice(
                                || format!("bit {} copy", index),
                                &mut region,
                                bits_columns[index],
                                offset,
                            )?
                        } else {
                            region.assign_advice(
                                || format!("bit {} copy", index),
                                bits_columns[index],
                                offset,
                                || Value::known(Bit::from(false)),
                            )?
                        };
                    }
                }

                region.assign_advice(|| "pack", self.config.fp.unwrap(), 0, || word.value_fp())
            },
        )
    }
}

#[derive(Clone)]
struct AssignedWordLogicalOperationsConfig {
    word_a: [Column<Advice>; 8],
    word_b: [Column<Advice>; 8],
    word_c: [Column<Advice>; 8],
    s_xor: Selector,
    s_and: Selector,
    s_not: Selector,
}
struct AssignedWordLogicalOperationsChip {
    config: AssignedWordLogicalOperationsConfig,
}
impl AssignedWordLogicalOperationsChip {
    fn construct(config: AssignedWordLogicalOperationsConfig) -> Self {
        AssignedWordLogicalOperationsChip { config }
    }

    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        word_a: [Column<Advice>; 8],
        word_b: [Column<Advice>; 8],
        word_c: [Column<Advice>; 8],
        s_xor: Selector,
        s_and: Selector,
        s_not: Selector,
    ) -> AssignedWordLogicalOperationsConfig {
        meta.create_gate("xor gate", |meta: &mut VirtualCells<Fp>| {
            // query XOR selector
            // query word_a bits
            // query word_b bits
            // query word_c bits (with XOR result)
            // return constraints

            let s_xor = meta.query_selector(s_xor);

            let a = (0..WORD_BIT_LEN / word_a.len())
                .into_iter()
                .flat_map(|rot| {
                    (0..word_a.len())
                        .into_iter()
                        .map(|col_index| meta.query_advice(word_a[col_index], Rotation(rot as i32)))
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>();

            let b = (0..WORD_BIT_LEN / word_b.len())
                .into_iter()
                .flat_map(|rot| {
                    (0..word_b.len())
                        .into_iter()
                        .map(|col_index| meta.query_advice(word_b[col_index], Rotation(rot as i32)))
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>();

            let out = (0..WORD_BIT_LEN / word_c.len())
                .into_iter()
                .flat_map(|rot| {
                    (0..word_c.len())
                        .into_iter()
                        .map(|col_index| meta.query_advice(word_c[col_index], Rotation(rot as i32)))
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>();

            Constraints::with_selector(
                s_xor,
                vec![
                    (
                        "bit 0 xor",
                        (a[0].clone() + a[0].clone()) * b[0].clone() - a[0].clone() - b[0].clone()
                            + out[0].clone(),
                    ),
                    (
                        "bit 1 xor",
                        (a[1].clone() + a[1].clone()) * b[1].clone() - a[1].clone() - b[1].clone()
                            + out[1].clone(),
                    ),
                    (
                        "bit 2 xor",
                        (a[2].clone() + a[2].clone()) * b[2].clone() - a[2].clone() - b[2].clone()
                            + out[2].clone(),
                    ),
                    (
                        "bit 3 xor",
                        (a[3].clone() + a[3].clone()) * b[3].clone() - a[3].clone() - b[3].clone()
                            + out[3].clone(),
                    ),
                    (
                        "bit 4 xor",
                        (a[4].clone() + a[4].clone()) * b[4].clone() - a[4].clone() - b[4].clone()
                            + out[4].clone(),
                    ),
                    (
                        "bit 5 xor",
                        (a[5].clone() + a[5].clone()) * b[5].clone() - a[5].clone() - b[5].clone()
                            + out[5].clone(),
                    ),
                    (
                        "bit 6 xor",
                        (a[6].clone() + a[6].clone()) * b[6].clone() - a[6].clone() - b[6].clone()
                            + out[6].clone(),
                    ),
                    (
                        "bit 7 xor",
                        (a[7].clone() + a[7].clone()) * b[7].clone() - a[7].clone() - b[7].clone()
                            + out[7].clone(),
                    ),
                    (
                        "bit 8 xor",
                        (a[8].clone() + a[8].clone()) * b[8].clone() - a[8].clone() - b[8].clone()
                            + out[8].clone(),
                    ),
                    (
                        "bit 9 xor",
                        (a[9].clone() + a[9].clone()) * b[9].clone() - a[9].clone() - b[9].clone()
                            + out[9].clone(),
                    ),
                    (
                        "bit 10 xor",
                        (a[10].clone() + a[10].clone()) * b[10].clone()
                            - a[10].clone()
                            - b[10].clone()
                            + out[10].clone(),
                    ),
                    (
                        "bit 11 xor",
                        (a[11].clone() + a[11].clone()) * b[11].clone()
                            - a[11].clone()
                            - b[11].clone()
                            + out[11].clone(),
                    ),
                    (
                        "bit 12 xor",
                        (a[12].clone() + a[12].clone()) * b[12].clone()
                            - a[12].clone()
                            - b[12].clone()
                            + out[12].clone(),
                    ),
                    (
                        "bit 13 xor",
                        (a[13].clone() + a[13].clone()) * b[13].clone()
                            - a[13].clone()
                            - b[13].clone()
                            + out[13].clone(),
                    ),
                    (
                        "bit 14 xor",
                        (a[14].clone() + a[14].clone()) * b[14].clone()
                            - a[14].clone()
                            - b[14].clone()
                            + out[14].clone(),
                    ),
                    (
                        "bit 15 xor",
                        (a[15].clone() + a[15].clone()) * b[15].clone()
                            - a[15].clone()
                            - b[15].clone()
                            + out[15].clone(),
                    ),
                    (
                        "bit 16 xor",
                        (a[16].clone() + a[16].clone()) * b[16].clone()
                            - a[16].clone()
                            - b[16].clone()
                            + out[16].clone(),
                    ),
                    (
                        "bit 17 xor",
                        (a[17].clone() + a[17].clone()) * b[17].clone()
                            - a[17].clone()
                            - b[17].clone()
                            + out[17].clone(),
                    ),
                    (
                        "bit 18 xor",
                        (a[18].clone() + a[18].clone()) * b[18].clone()
                            - a[18].clone()
                            - b[18].clone()
                            + out[18].clone(),
                    ),
                    (
                        "bit 19 xor",
                        (a[19].clone() + a[19].clone()) * b[19].clone()
                            - a[19].clone()
                            - b[19].clone()
                            + out[19].clone(),
                    ),
                    (
                        "bit 20 xor",
                        (a[20].clone() + a[20].clone()) * b[20].clone()
                            - a[20].clone()
                            - b[20].clone()
                            + out[20].clone(),
                    ),
                    (
                        "bit 21 xor",
                        (a[21].clone() + a[21].clone()) * b[21].clone()
                            - a[21].clone()
                            - b[21].clone()
                            + out[21].clone(),
                    ),
                    (
                        "bit 22 xor",
                        (a[22].clone() + a[22].clone()) * b[22].clone()
                            - a[22].clone()
                            - b[22].clone()
                            + out[22].clone(),
                    ),
                    (
                        "bit 23 xor",
                        (a[23].clone() + a[23].clone()) * b[23].clone()
                            - a[23].clone()
                            - b[23].clone()
                            + out[23].clone(),
                    ),
                    (
                        "bit 24 xor",
                        (a[24].clone() + a[24].clone()) * b[24].clone()
                            - a[24].clone()
                            - b[24].clone()
                            + out[24].clone(),
                    ),
                    (
                        "bit 25 xor",
                        (a[25].clone() + a[25].clone()) * b[25].clone()
                            - a[25].clone()
                            - b[25].clone()
                            + out[25].clone(),
                    ),
                    (
                        "bit 26 xor",
                        (a[26].clone() + a[26].clone()) * b[26].clone()
                            - a[26].clone()
                            - b[26].clone()
                            + out[26].clone(),
                    ),
                    (
                        "bit 27 xor",
                        (a[27].clone() + a[27].clone()) * b[27].clone()
                            - a[27].clone()
                            - b[27].clone()
                            + out[27].clone(),
                    ),
                    (
                        "bit 28 xor",
                        (a[28].clone() + a[28].clone()) * b[28].clone()
                            - a[28].clone()
                            - b[28].clone()
                            + out[28].clone(),
                    ),
                    (
                        "bit 29 xor",
                        (a[29].clone() + a[29].clone()) * b[29].clone()
                            - a[29].clone()
                            - b[29].clone()
                            + out[29].clone(),
                    ),
                    (
                        "bit 30 xor",
                        (a[30].clone() + a[30].clone()) * b[30].clone()
                            - a[30].clone()
                            - b[30].clone()
                            + out[30].clone(),
                    ),
                    (
                        "bit 31 xor",
                        (a[31].clone() + a[31].clone()) * b[31].clone()
                            - a[31].clone()
                            - b[31].clone()
                            + out[31].clone(),
                    ),
                ],
            )
        });

        meta.create_gate("and gate", |meta: &mut VirtualCells<Fp>| {
            // query AND selector
            // query word_a bits
            // query word_b bits
            // query word_c bits (with AND result)
            // return constraints

            let s_xor = meta.query_selector(s_and);

            let a = (0..WORD_BIT_LEN / word_a.len())
                .into_iter()
                .flat_map(|rot| {
                    (0..word_a.len())
                        .into_iter()
                        .map(|col_index| meta.query_advice(word_a[col_index], Rotation(rot as i32)))
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>();

            let b = (0..WORD_BIT_LEN / word_b.len())
                .into_iter()
                .flat_map(|rot| {
                    (0..word_b.len())
                        .into_iter()
                        .map(|col_index| meta.query_advice(word_b[col_index], Rotation(rot as i32)))
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>();

            let out = (0..WORD_BIT_LEN / word_c.len())
                .into_iter()
                .flat_map(|rot| {
                    (0..word_c.len())
                        .into_iter()
                        .map(|col_index| meta.query_advice(word_c[col_index], Rotation(rot as i32)))
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>();

            Constraints::with_selector(
                s_xor,
                vec![
                    ("bit 0 and", a[0].clone() * b[0].clone() - out[0].clone()),
                    ("bit 1 and", a[1].clone() * b[1].clone() - out[1].clone()),
                    ("bit 2 and", a[2].clone() * b[2].clone() - out[2].clone()),
                    ("bit 3 and", a[3].clone() * b[3].clone() - out[3].clone()),
                    ("bit 4 and", a[4].clone() * b[4].clone() - out[4].clone()),
                    ("bit 5 and", a[5].clone() * b[5].clone() - out[5].clone()),
                    ("bit 6 and", a[6].clone() * b[6].clone() - out[6].clone()),
                    ("bit 7 and", a[7].clone() * b[7].clone() - out[7].clone()),
                    ("bit 8 and", a[8].clone() * b[8].clone() - out[8].clone()),
                    ("bit 9 and", a[9].clone() * b[9].clone() - out[9].clone()),
                    (
                        "bit 10 and",
                        a[10].clone() * b[10].clone() - out[10].clone(),
                    ),
                    (
                        "bit 11 and",
                        a[11].clone() * b[11].clone() - out[11].clone(),
                    ),
                    (
                        "bit 12 and",
                        a[12].clone() * b[12].clone() - out[12].clone(),
                    ),
                    (
                        "bit 13 and",
                        a[13].clone() * b[13].clone() - out[13].clone(),
                    ),
                    (
                        "bit 14 and",
                        a[14].clone() * b[14].clone() - out[14].clone(),
                    ),
                    (
                        "bit 15 and",
                        a[15].clone() * b[15].clone() - out[15].clone(),
                    ),
                    (
                        "bit 16 and",
                        a[16].clone() * b[16].clone() - out[16].clone(),
                    ),
                    (
                        "bit 17 and",
                        a[17].clone() * b[17].clone() - out[17].clone(),
                    ),
                    (
                        "bit 18 and",
                        a[18].clone() * b[18].clone() - out[18].clone(),
                    ),
                    (
                        "bit 19 and",
                        a[19].clone() * b[19].clone() - out[19].clone(),
                    ),
                    (
                        "bit 20 and",
                        a[20].clone() * b[20].clone() - out[20].clone(),
                    ),
                    (
                        "bit 21 and",
                        a[21].clone() * b[21].clone() - out[21].clone(),
                    ),
                    (
                        "bit 22 and",
                        a[22].clone() * b[22].clone() - out[22].clone(),
                    ),
                    (
                        "bit 23 and",
                        a[23].clone() * b[23].clone() - out[23].clone(),
                    ),
                    (
                        "bit 24 and",
                        a[24].clone() * b[24].clone() - out[24].clone(),
                    ),
                    (
                        "bit 25 and",
                        a[25].clone() * b[25].clone() - out[25].clone(),
                    ),
                    (
                        "bit 26 and",
                        a[26].clone() * b[26].clone() - out[26].clone(),
                    ),
                    (
                        "bit 27 and",
                        a[27].clone() * b[27].clone() - out[27].clone(),
                    ),
                    (
                        "bit 28 and",
                        a[28].clone() * b[28].clone() - out[28].clone(),
                    ),
                    (
                        "bit 29 and",
                        a[29].clone() * b[29].clone() - out[29].clone(),
                    ),
                    (
                        "bit 30 and",
                        a[30].clone() * b[30].clone() - out[30].clone(),
                    ),
                    (
                        "bit 31 and",
                        a[31].clone() * b[31].clone() - out[31].clone(),
                    ),
                ],
            )
        });

        meta.create_gate("not gate", |meta: &mut VirtualCells<Fp>| {
            // query selector
            // query word_a bits
            // query word_c bits (with NOT result)
            // return constraints

            let s_not = meta.query_selector(s_not);

            let a = (0..WORD_BIT_LEN / word_a.len())
                .into_iter()
                .flat_map(|rot| {
                    (0..word_a.len())
                        .into_iter()
                        .map(|col_index| meta.query_advice(word_a[col_index], Rotation(rot as i32)))
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>();

            let out = (0..WORD_BIT_LEN / word_c.len())
                .into_iter()
                .flat_map(|rot| {
                    (0..word_c.len())
                        .into_iter()
                        .map(|col_index| meta.query_advice(word_c[col_index], Rotation(rot as i32)))
                        .collect::<Vec<Expression<Fp>>>()
                })
                .collect::<Vec<Expression<Fp>>>();

            Constraints::with_selector(
                s_not,
                vec![
                    ("bit 0 not", a[0].clone() * out[0].clone()),
                    ("bit 1 not", a[1].clone() * out[1].clone()),
                    ("bit 2 not", a[2].clone() * out[2].clone()),
                    ("bit 3 not", a[3].clone() * out[3].clone()),
                    ("bit 4 not", a[4].clone() * out[4].clone()),
                    ("bit 5 not", a[5].clone() * out[5].clone()),
                    ("bit 6 not", a[6].clone() * out[6].clone()),
                    ("bit 7 not", a[7].clone() * out[7].clone()),
                    ("bit 8 not", a[8].clone() * out[8].clone()),
                    ("bit 9 not", a[9].clone() * out[9].clone()),
                    ("bit 10 not", a[10].clone() * out[10].clone()),
                    ("bit 11 not", a[11].clone() * out[11].clone()),
                    ("bit 12 not", a[12].clone() * out[12].clone()),
                    ("bit 13 not", a[13].clone() * out[13].clone()),
                    ("bit 14 not", a[14].clone() * out[14].clone()),
                    ("bit 15 not", a[15].clone() * out[15].clone()),
                    ("bit 16 not", a[16].clone() * out[16].clone()),
                    ("bit 17 not", a[17].clone() * out[17].clone()),
                    ("bit 18 not", a[18].clone() * out[18].clone()),
                    ("bit 19 not", a[19].clone() * out[19].clone()),
                    ("bit 20 not", a[20].clone() * out[20].clone()),
                    ("bit 21 not", a[21].clone() * out[21].clone()),
                    ("bit 22 not", a[22].clone() * out[22].clone()),
                    ("bit 23 not", a[23].clone() * out[23].clone()),
                    ("bit 24 not", a[24].clone() * out[24].clone()),
                    ("bit 25 not", a[25].clone() * out[25].clone()),
                    ("bit 26 not", a[26].clone() * out[26].clone()),
                    ("bit 27 not", a[27].clone() * out[27].clone()),
                    ("bit 28 not", a[28].clone() * out[28].clone()),
                    ("bit 29 not", a[29].clone() * out[29].clone()),
                    ("bit 30 not", a[30].clone() * out[30].clone()),
                    ("bit 31 not", a[31].clone() * out[31].clone()),
                ],
            )
        });

        AssignedWordLogicalOperationsConfig {
            word_a,
            word_b,
            word_c,
            s_xor,
            s_and,
            s_not,
        }
    }

    fn not(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedWord,
        expected_not_a: u32,
    ) -> Result<AssignedWord, Error> {
        layouter.assign_region(
            || "not",
            |mut region| {
                // assign/copy a bits
                // compute its NOT at high level and pass it as input parameter
                // assign it

                self.config.s_not.enable(&mut region, 0)?;

                let _ = a.bits
                    .chunks(self.config.word_a.len())
                    .into_iter()
                    .enumerate()
                    .flat_map(|(offset, word)| {
                        assert_eq!(word.len(), self.config.word_a.len());

                        word.into_iter()
                            .enumerate()
                            .map(|(bit_index, bit)| {
                                let bit = bit.as_ref();
                                match bit {
                                    Some(v) => v.copy_advice(
                                        || "assign a",
                                        &mut region,
                                        self.config.word_a[bit_index],
                                        offset,
                                    ),
                                    None => region.assign_advice(
                                        || "assign a",
                                        self.config.word_a[bit_index],
                                        offset,
                                        || Value::known(Bit::from(false)),
                                    ),
                                }
                                .unwrap()
                            })
                            .collect::<Vec<AssignedCell<Bit, Fp>>>()
                    })
                    .collect::<Vec<AssignedCell<Bit, Fp>>>();

                let expected_bits = u32_to_bits_be(expected_not_a);

                let not_assigned = expected_bits
                    .chunks(self.config.word_c.len())
                    .into_iter()
                    .enumerate()
                    .flat_map(|(index, bits)| {
                        bits.into_iter()
                            .enumerate()
                            .map(|(bit_chunk_index, bit)| {
                                region
                                    .assign_advice(
                                        || "assign result",
                                        self.config.word_c[bit_chunk_index],
                                        index,
                                        || Value::known(Bit::from(*bit)),
                                    )
                                    .unwrap()
                            })
                            .collect::<Vec<AssignedCell<Bit, Fp>>>()
                    })
                    .collect::<Vec<AssignedCell<Bit, Fp>>>();

                let not_assigned = AssignedWord {
                    bits: not_assigned.into_iter().map(Some).collect(),
                };

                not_assigned
                    .value_u32()
                    .map(|computed| assert_eq!(expected_not_a, computed));

                Ok(not_assigned)
            },
        )
    }

    fn and(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedWord,
        b: AssignedWord,
        expected_and: u32,
    ) -> Result<AssignedWord, Error> {
        layouter.assign_region(
            || "and",
            |mut region| {
                // assign/copy a bits
                // assign/copy b bits
                // compute their AND at high level and pass it as input parameter
                // assign it

                self.config.s_and.enable(&mut region, 0)?;

                let _ = a.bits
                    .chunks(self.config.word_a.len())
                    .into_iter()
                    .enumerate()
                    .flat_map(|(offset, word)| {
                        assert_eq!(word.len(), self.config.word_a.len());

                        word.into_iter()
                            .enumerate()
                            .map(|(bit_index, bit)| {
                                let bit = bit.as_ref();
                                match bit {
                                    Some(v) => v.copy_advice(
                                        || "assign a",
                                        &mut region,
                                        self.config.word_a[bit_index],
                                        offset,
                                    ),
                                    None => region.assign_advice(
                                        || "assign a",
                                        self.config.word_a[bit_index],
                                        offset,
                                        || Value::known(Bit::from(false)),
                                    ),
                                }
                                .unwrap()
                            })
                            .collect::<Vec<AssignedCell<Bit, Fp>>>()
                    })
                    .collect::<Vec<AssignedCell<Bit, Fp>>>();

                let _ = b.bits
                    .chunks(self.config.word_b.len())
                    .into_iter()
                    .enumerate()
                    .flat_map(|(offset, word)| {
                        assert_eq!(word.len(), self.config.word_b.len());

                        word.into_iter()
                            .enumerate()
                            .map(|(bit_index, bit)| {
                                let bit = bit.as_ref();
                                match bit {
                                    Some(v) => v.copy_advice(
                                        || "assign b",
                                        &mut region,
                                        self.config.word_b[bit_index],
                                        offset,
                                    ),
                                    None => region.assign_advice(
                                        || "assign b",
                                        self.config.word_b[bit_index],
                                        offset,
                                        || Value::known(Bit::from(false)),
                                    ),
                                }
                                .unwrap()
                            })
                            .collect::<Vec<AssignedCell<Bit, Fp>>>()
                    })
                    .collect::<Vec<AssignedCell<Bit, Fp>>>();

                let expected_bits = u32_to_bits_be(expected_and);

                let and_assigned = expected_bits
                    .chunks(self.config.word_c.len())
                    .into_iter()
                    .enumerate()
                    .flat_map(|(index, bits)| {
                        bits.into_iter()
                            .enumerate()
                            .map(|(bit_chunk_index, bit)| {
                                region
                                    .assign_advice(
                                        || "assign result",
                                        self.config.word_c[bit_chunk_index],
                                        index,
                                        || Value::known(Bit::from(*bit)),
                                    )
                                    .unwrap()
                            })
                            .collect::<Vec<AssignedCell<Bit, Fp>>>()
                    })
                    .collect::<Vec<AssignedCell<Bit, Fp>>>();

                let and_assigned = AssignedWord {
                    bits: and_assigned.into_iter().map(Some).collect(),
                };

                and_assigned
                    .value_u32()
                    .map(|computed| assert_eq!(expected_and, computed));

                Ok(and_assigned)
            },
        )
    }

    fn xor(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedWord,
        b: AssignedWord,
        expected_xor: u32,
    ) -> Result<AssignedWord, Error> {
        layouter.assign_region(
            || "xor",
            |mut region| {
                // assign/copy a bits
                // assign/copy b bits
                // compute their XOR at high-level and pass it as input parameter
                // assign it

                self.config.s_xor.enable(&mut region, 0)?;

                let _ = a.bits
                    .chunks(self.config.word_a.len())
                    .into_iter()
                    .enumerate()
                    .flat_map(|(offset, word)| {
                        assert_eq!(word.len(), self.config.word_a.len());

                        word.into_iter()
                            .enumerate()
                            .map(|(bit_index, bit)| {
                                let bit = bit.as_ref();
                                match bit {
                                    Some(v) => v.copy_advice(
                                        || "assign a",
                                        &mut region,
                                        self.config.word_a[bit_index],
                                        offset,
                                    ),
                                    None => region.assign_advice(
                                        || "assign a",
                                        self.config.word_a[bit_index],
                                        offset,
                                        || Value::known(Bit::from(false)),
                                    ),
                                }
                                .unwrap()
                            })
                            .collect::<Vec<AssignedCell<Bit, Fp>>>()
                    })
                    .collect::<Vec<AssignedCell<Bit, Fp>>>();

                let _ = b.bits
                    .chunks(self.config.word_b.len())
                    .into_iter()
                    .enumerate()
                    .flat_map(|(offset, word)| {
                        assert_eq!(word.len(), self.config.word_b.len());

                        word.into_iter()
                            .enumerate()
                            .map(|(bit_index, bit)| {
                                let bit = bit.as_ref();
                                match bit {
                                    Some(v) => v.copy_advice(
                                        || "assign b",
                                        &mut region,
                                        self.config.word_b[bit_index],
                                        offset,
                                    ),
                                    None => region.assign_advice(
                                        || "assign b",
                                        self.config.word_b[bit_index],
                                        offset,
                                        || Value::known(Bit::from(false)),
                                    ),
                                }
                                .unwrap()
                            })
                            .collect::<Vec<AssignedCell<Bit, Fp>>>()
                    })
                    .collect::<Vec<AssignedCell<Bit, Fp>>>();

                let expected_bits = u32_to_bits_be(expected_xor);

                let xor_assigned = expected_bits
                    .chunks(self.config.word_c.len())
                    .into_iter()
                    .enumerate()
                    .flat_map(|(index, bits)| {
                        bits.into_iter()
                            .enumerate()
                            .map(|(bit_chunk_index, bit)| {
                                region
                                    .assign_advice(
                                        || "assign result",
                                        self.config.word_c[bit_chunk_index],
                                        index,
                                        || Value::known(Bit::from(*bit)),
                                    )
                                    .unwrap()
                            })
                            .collect::<Vec<AssignedCell<Bit, Fp>>>()
                    })
                    .collect::<Vec<AssignedCell<Bit, Fp>>>();

                let xor_assigned = AssignedWord {
                    bits: xor_assigned.into_iter().map(Some).collect(),
                };

                xor_assigned
                    .value_u32()
                    .map(|computed| assert_eq!(expected_xor, computed));

                Ok(xor_assigned)
            },
        )
    }
}

struct Sha256OneRoundCircuit {
    block: [bool; 512],
    state: [u32; 8],
}

impl Sha256OneRoundCircuit {
    fn k(&self) -> u32 {
        13
    }
}

impl Circuit<Fp> for Sha256OneRoundCircuit {
    //type Config = Sha256Config;
    type Config = (
        Sha256Config,
        //BooleanOperationsConfig,
        AssignedWordLogicalOperationsConfig,
        U32WordModularAddConfig,
    );
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        meta.instance_column(); // unused

        let word = (0..8)
            .into_iter()
            .map(|_| {
                let word = meta.advice_column();
                meta.enable_equality(word);
                word
            })
            .collect::<Vec<Column<Advice>>>();

        let s_word = meta.selector();

        let advice1 = meta.advice_column();
        let s_pack = meta.selector();

        meta.enable_equality(advice1);

        let word_b = (0..8)
            .into_iter()
            .map(|_| {
                let word = meta.advice_column();
                meta.enable_equality(word);
                word
            })
            .collect::<Vec<Column<Advice>>>();

        let sha256_config = Sha256Chip::configure(
            meta,
            [
                word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
            ],
            s_word,
            Some(advice1),
            Some([
                word_b[0], word_b[1], word_b[2], word_b[3], word_b[4], word_b[5], word_b[6],
                word_b[7],
            ]),
            Some(s_pack),
        );

        let word_c = (0..8)
            .into_iter()
            .map(|_| {
                let word = meta.advice_column();
                meta.enable_equality(word);
                word
            })
            .collect::<Vec<Column<Advice>>>();

        let s_xor_word = meta.selector();
        let s_and_word = meta.selector();
        let s_not_word = meta.selector();

        let assigned_word_config = AssignedWordLogicalOperationsChip::configure(
            meta,
            [
                word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
            ],
            [
                word_b[0], word_b[1], word_b[2], word_b[3], word_b[4], word_b[5], word_b[6],
                word_b[7],
            ],
            [
                word_c[0], word_c[1], word_c[2], word_c[3], word_c[4], word_c[5], word_c[6],
                word_c[7],
            ],
            s_xor_word,
            s_and_word,
            s_not_word,
        );

        // running_sum requires this
        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        let s_range_check = meta.selector();
        let s_modular_add = meta.selector();

        let modular_add_config = U32WordModularAddChip::configure(
            meta,
            word[0],
            s_range_check,
            word[1],
            word[2],
            s_modular_add,
            word[3],
            word[4],
        );

        (sha256_config, assigned_word_config, modular_add_config)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let h_expected = sha256_process_single_block(self.block.as_slice(), self.state);

        let sha256chip = Sha256Chip::construct(config.0);
        let assigned_word_operations = AssignedWordLogicalOperationsChip::construct(config.1);
        let u32word_modular_add_chip = U32WordModularAddChip::construct(config.2);

        let mut assigned_state = vec![];

        // load state

        for (index, word) in self.state.iter().enumerate() {
            let assigned_state_word = sha256chip.load_word(
                layouter.namespace(|| format!("load_state_word_{}", index)),
                Some(u32_to_bits_be(*word).try_into().unwrap()),
            )?;

            assigned_state.push(AssignedWord {
                bits: assigned_state_word
                    .into_iter()
                    .map(Some)
                    .collect::<Vec<Option<AssignedCell<Bit, Fp>>>>()
                    .try_into()
                    .unwrap(),
            });
        }

        assert_eq!(self.block.len(), 512);
        let mut assigned_block = vec![];

        // load block (w[0] .. w[15])
        for (index, word) in self.block.chunks(WORD_BIT_LEN).into_iter().enumerate() {
            let assigned_block_word = sha256chip.load_word(
                layouter.namespace(|| format!("load_block_word_{}", index)),
                Some(word.try_into().unwrap()),
            )?;
            assigned_block.push(AssignedWord {
                bits: assigned_block_word
                    .into_iter()
                    .map(Some)
                    .collect::<Vec<Option<AssignedCell<Bit, Fp>>>>()
                    .try_into()
                    .unwrap(),
            });
        }

        // load block (w[16] .. w[63])
        for index in 16..64 {
            let assigned_block_word = sha256chip.load_word(
                layouter.namespace(|| format!("load_block_word_{}", index)),
                Some(u32_to_bits_be(0).try_into().unwrap()),
            )?;
            assigned_block.push(AssignedWord {
                bits: assigned_block_word.into_iter().map(Some).collect(),
            });
        }

        for index in 16..64 {
            let mut layouter = layouter.namespace(|| format!("1 loop iteration {}", index));

            let shifted_3 = assigned_block[index - 15].shr(3).clone();
            let rotated_7 = assigned_block[index - 15].rotr(7).clone();
            let rotated_18 = assigned_block[index - 15].rotr(18).clone();

            let mut expected_xor = 0;
            rotated_7
                .value_u32()
                .zip(rotated_18.value_u32())
                .map(|(a, b)| expected_xor = a ^ b);

            let xor1 = assigned_word_operations.xor(
                layouter.namespace(|| format!("s0 xor1")),
                rotated_7,
                rotated_18,
                expected_xor,
            )?;

            let mut expected_xor = 0;
            xor1.value_u32()
                .zip(shifted_3.value_u32())
                .map(|(a, b)| expected_xor = a ^ b);

            let s0 = assigned_word_operations.xor(
                layouter.namespace(|| format!("s0")),
                xor1,
                shifted_3,
                expected_xor,
            )?;

            let shifted_10 = assigned_block[index - 2].shr(10).clone();
            let rotated_17 = assigned_block[index - 2].rotr(17).clone();
            let rotated_19 = assigned_block[index - 2].rotr(19).clone();

            let mut expected_xor = 0;
            rotated_17
                .value_u32()
                .zip(rotated_19.value_u32())
                .map(|(a, b)| expected_xor = a ^ b);

            let xor1 = assigned_word_operations.xor(
                layouter.namespace(|| format!("s1 xor1")),
                rotated_17,
                rotated_19,
                expected_xor,
            )?;

            let mut expected_xor = 0;
            xor1.value_u32()
                .zip(shifted_10.value_u32())
                .map(|(a, b)| expected_xor = a ^ b);

            let s1 = assigned_word_operations.xor(
                layouter.namespace(|| format!("s1")),
                xor1,
                shifted_10,
                expected_xor,
            )?;

            let s0_packed = sha256chip.pack_word(layouter.namespace(|| "pack s0"), s0)?;

            let s1_packed = sha256chip.pack_word(layouter.namespace(|| "pack s1"), s1)?;

            let w_16 = sha256chip.pack_word(
                layouter.namespace(|| "pack w[index - 16]"),
                assigned_block[index - 16].clone(),
            )?;

            let w_7 = sha256chip.pack_word(
                layouter.namespace(|| "pack w[index - 7]"),
                assigned_block[index - 7].clone(),
            )?;

            let add1 = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "add1"),
                s0_packed,
                s1_packed,
            )?;

            let add2 =
                u32word_modular_add_chip.modular_add(layouter.namespace(|| "add2"), add1, w_7)?;

            let result = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "result"),
                add2,
                w_16,
            )?;

            let mut result_bits = vec![];
            result.value().map(|x| {
                for bit in x.to_le_bits() {
                    result_bits.push(bit)
                }
            });

            let new_block_word = if !result_bits.is_empty() {
                let result_bits = &mut result_bits[0..32];
                sha256chip.load_word(
                    layouter.namespace(|| format!("reassign block {}", index)),
                    Some(result_bits.try_into().unwrap()),
                )?
            } else {
                sha256chip.load_word(
                    layouter.namespace(|| format!("reassign block {}", index)),
                    None,
                )?
            };

            assigned_block[index] = AssignedWord {
                bits: new_block_word.into_iter().map(Some).collect(),
            };
        }

        let mut a = assigned_state[0].clone();
        let mut b = assigned_state[1].clone();
        let mut c = assigned_state[2].clone();
        let mut d = assigned_state[3].clone();
        let mut e = assigned_state[4].clone();
        let mut f = assigned_state[5].clone();
        let mut g = assigned_state[6].clone();
        let mut h = assigned_state[7].clone();

        for index in 0..64 {
            let mut layouter = layouter.namespace(|| format!("2 loop iteration {}", index));
            let e_rotated_6 = e.clone().rotr(6);
            let e_rotated_11 = e.clone().rotr(11);
            let e_rotated_25 = e.clone().rotr(25);

            let mut expected_xor = 0;
            e_rotated_6
                .value_u32()
                .zip(e_rotated_11.value_u32())
                .map(|(a, b)| expected_xor = a ^ b);

            let xor1 = assigned_word_operations.xor(
                layouter.namespace(|| format!("s1 xor1")),
                e_rotated_6,
                e_rotated_11,
                expected_xor,
            )?;

            let mut expected_xor = 0;
            xor1.value_u32()
                .zip(e_rotated_25.value_u32())
                .map(|(a, b)| expected_xor = a ^ b);

            let s1 = assigned_word_operations.xor(
                layouter.namespace(|| format!("s1")),
                xor1,
                e_rotated_25,
                expected_xor,
            )?;

            let mut expected_and = 0;
            e.value_u32()
                .zip(f.value_u32())
                .map(|(e, f)| expected_and = e & f);
            let e_and_f = assigned_word_operations.and(
                layouter.namespace(|| format!("e and f")),
                e.clone(),
                f.clone(),
                expected_and,
            )?;

            let mut expected_not_e = 0;
            e.value_u32().map(|e| expected_not_e = !e);
            let not_e = assigned_word_operations.not(
                layouter.namespace(|| format!("not e")),
                e.clone(),
                expected_not_e,
            )?;

            let mut expected_and = 0;
            not_e
                .value_u32()
                .zip(g.value_u32())
                .map(|(not_e, g)| expected_and = not_e & g);
            let not_e_and_g = assigned_word_operations.and(
                layouter.namespace(|| format!("not_e and g")),
                not_e.clone(),
                g.clone(),
                expected_and,
            )?;

            let mut ch = 0;
            e_and_f
                .value_u32()
                .zip(not_e_and_g.value_u32())
                .map(|(left, right)| ch = left ^ right);
            let ch = assigned_word_operations.xor(
                layouter.namespace(|| "ch"),
                e_and_f.clone(),
                not_e_and_g.clone(),
                ch,
            )?;

            let a_rotated_2 = a.rotr(2);
            let a_rotated_13 = a.rotr(13);
            let a_rotated_22 = a.rotr(22);

            let mut expected_xor = 0;
            a_rotated_2
                .value_u32()
                .zip(a_rotated_13.value_u32())
                .map(|(left, right)| expected_xor = left ^ right);
            let xor1 = assigned_word_operations.xor(
                layouter.namespace(|| "s0 xor1"),
                a_rotated_2.clone(),
                a_rotated_13.clone(),
                expected_xor,
            )?;

            let mut expected_xor = 0;
            xor1.value_u32()
                .zip(a_rotated_22.value_u32())
                .map(|(left, right)| expected_xor = left ^ right);
            let s0 = assigned_word_operations.xor(
                layouter.namespace(|| "s0"),
                xor1.clone(),
                a_rotated_22.clone(),
                expected_xor,
            )?;

            let mut expected_and = 0;
            a.value_u32()
                .zip(b.value_u32())
                .map(|(left, right)| expected_and = left & right);
            let a_and_b = assigned_word_operations.and(
                layouter.namespace(|| "a and b"),
                a.clone(),
                b.clone(),
                expected_and,
            )?;

            let mut expected_and = 0;
            a.value_u32()
                .zip(c.value_u32())
                .map(|(left, right)| expected_and = left & right);
            let a_and_c = assigned_word_operations.and(
                layouter.namespace(|| "a and c"),
                a.clone(),
                c.clone(),
                expected_and,
            )?;

            let mut expected_and = 0;
            b.value_u32()
                .zip(c.value_u32())
                .map(|(left, right)| expected_and = left & right);
            let b_and_c = assigned_word_operations.and(
                layouter.namespace(|| "b and c"),
                b.clone(),
                c.clone(),
                expected_and,
            )?;

            let mut expected_xor = 0;
            a_and_b
                .value_u32()
                .zip(a_and_c.value_u32())
                .map(|(left, right)| expected_xor = left ^ right);
            let xor1 = assigned_word_operations.xor(
                layouter.namespace(|| "maj xor1"),
                a_and_b.clone(),
                a_and_c.clone(),
                expected_xor,
            )?;

            let mut expected_xor = 0;
            xor1.value_u32()
                .zip(b_and_c.value_u32())
                .map(|(left, right)| expected_xor = left ^ right);
            let maj = assigned_word_operations.xor(
                layouter.namespace(|| "maj"),
                xor1.clone(),
                b_and_c.clone(),
                expected_xor,
            )?;

            let h_packed = sha256chip.pack_word(layouter.namespace(|| "pack h"), h.clone())?;

            let s1_packed = sha256chip.pack_word(layouter.namespace(|| "pack s1"), s1)?;

            let ch_packed = sha256chip.pack_word(layouter.namespace(|| "pack ch"), ch)?;

            let w_index = sha256chip.pack_word(
                layouter.namespace(|| "pack w_index"),
                assigned_block[index].clone(),
            )?;

            let add1 = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "add1"),
                h_packed,
                s1_packed,
            )?;

            let add2 = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "add2"),
                add1,
                ch_packed,
            )?;

            let add3 = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "add3"),
                add2,
                w_index,
            )?;

            let round_constant_index = u32_to_bits_be(ROUND_CONSTANTS[index]);
            let round_constant_index = sha256chip.load_word(
                layouter.namespace(|| "load round constant"),
                Some(round_constant_index.try_into().unwrap()),
            )?;

            let round_constant_index = AssignedWord {
                bits: round_constant_index.into_iter().map(Some).collect(),
            };
            let round_constant_index = sha256chip.pack_word(
                layouter.namespace(|| "pack round_constant_index"),
                round_constant_index,
            )?;

            let tmp1 = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "add4"),
                add3,
                round_constant_index,
            )?;

            h = g.clone();
            g = f.clone();
            f = e.clone();

            let d_packed = sha256chip.pack_word(layouter.namespace(|| "pack d"), d.clone())?;
            let e_computed = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "compute e"),
                d_packed,
                tmp1.clone(),
            )?;

            let mut e_bits = vec![];
            e_computed.value().map(|x| {
                for bit in x.to_le_bits() {
                    e_bits.push(bit)
                }
            });

            let e_bits = if !e_bits.is_empty() {
                let e_bits = &mut e_bits[0..32];
                sha256chip.load_word(
                    layouter.namespace(|| "load computed e"),
                    Some(e_bits.try_into().unwrap()),
                )?
            } else {
                sha256chip.load_word(layouter.namespace(|| "load computed e"), None)?
            };

            e = AssignedWord {
                bits: e_bits.into_iter().map(Some).collect(),
            };

            d = c.clone();
            c = b.clone();
            b = a.clone();
            let s0_packed = sha256chip.pack_word(layouter.namespace(|| "pack s0"), s0)?;
            let add1 = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "a add1"),
                tmp1.clone(),
                s0_packed,
            )?;
            let maj_packed = sha256chip.pack_word(layouter.namespace(|| "pack maj"), maj)?;
            let a_computed = u32word_modular_add_chip.modular_add(
                layouter.namespace(|| "a add2"),
                add1,
                maj_packed,
            )?;

            let mut a_bits = vec![];
            a_computed.value().map(|x| {
                for bit in x.to_le_bits() {
                    a_bits.push(bit)
                }
            });

            let a_bits = if !a_bits.is_empty() {
                let a_bits = &mut a_bits[0..32];
                sha256chip.load_word(
                    layouter.namespace(|| "load computed a"),
                    Some(a_bits.try_into().unwrap()),
                )?
            } else {
                sha256chip.load_word(layouter.namespace(|| "load computed a"), None)?
            };

            a = AssignedWord {
                bits: a_bits.into_iter().map(Some).collect(),
            };
        }

        let assigned_state_0 = sha256chip.pack_word(
            layouter.namespace(|| "pack assigned_state[0]"),
            assigned_state[0].clone(),
        )?;
        let a_packed = sha256chip.pack_word(layouter.namespace(|| "pack a"), a.clone())?;
        let h0 = u32word_modular_add_chip.modular_add(
            layouter.namespace(|| "h0"),
            assigned_state_0,
            a_packed,
        )?;

        let assigned_state_1 = sha256chip.pack_word(
            layouter.namespace(|| "pack assigned_state[1]"),
            assigned_state[1].clone(),
        )?;
        let b_packed = sha256chip.pack_word(layouter.namespace(|| "pack b"), b.clone())?;
        let h1 = u32word_modular_add_chip.modular_add(
            layouter.namespace(|| "h1"),
            assigned_state_1,
            b_packed,
        )?;

        let assigned_state_2 = sha256chip.pack_word(
            layouter.namespace(|| "pack assigned_state[2]"),
            assigned_state[2].clone(),
        )?;
        let c_packed = sha256chip.pack_word(layouter.namespace(|| "pack c"), c.clone())?;
        let h2 = u32word_modular_add_chip.modular_add(
            layouter.namespace(|| "h2"),
            assigned_state_2,
            c_packed,
        )?;

        let assigned_state_3 = sha256chip.pack_word(
            layouter.namespace(|| "pack assigned_state[3]"),
            assigned_state[3].clone(),
        )?;
        let d_packed = sha256chip.pack_word(layouter.namespace(|| "pack d"), d.clone())?;
        let h3 = u32word_modular_add_chip.modular_add(
            layouter.namespace(|| "h3"),
            assigned_state_3,
            d_packed,
        )?;

        let assigned_state_4 = sha256chip.pack_word(
            layouter.namespace(|| "pack assigned_state[4]"),
            assigned_state[4].clone(),
        )?;
        let e_packed = sha256chip.pack_word(layouter.namespace(|| "pack e"), e.clone())?;
        let h4 = u32word_modular_add_chip.modular_add(
            layouter.namespace(|| "h4"),
            assigned_state_4,
            e_packed,
        )?;

        let assigned_state_5 = sha256chip.pack_word(
            layouter.namespace(|| "pack assigned_state[5]"),
            assigned_state[5].clone(),
        )?;
        let f_packed = sha256chip.pack_word(layouter.namespace(|| "pack f"), f.clone())?;
        let h5 = u32word_modular_add_chip.modular_add(
            layouter.namespace(|| "h5"),
            assigned_state_5,
            f_packed,
        )?;

        let assigned_state_6 = sha256chip.pack_word(
            layouter.namespace(|| "pack assigned_state[6]"),
            assigned_state[6].clone(),
        )?;
        let g_packed = sha256chip.pack_word(layouter.namespace(|| "pack g"), g.clone())?;
        let h6 = u32word_modular_add_chip.modular_add(
            layouter.namespace(|| "h6"),
            assigned_state_6,
            g_packed,
        )?;

        let assigned_state_7 = sha256chip.pack_word(
            layouter.namespace(|| "pack assigned_state[7]"),
            assigned_state[7].clone(),
        )?;
        let h_packed = sha256chip.pack_word(layouter.namespace(|| "pack h"), h.clone())?;
        let h7 = u32word_modular_add_chip.modular_add(
            layouter.namespace(|| "h7"),
            assigned_state_7,
            h_packed,
        )?;

        let h_actual = vec![h0, h1, h2, h3, h4, h5, h6, h7];

        for index in 0..8 {
            h_actual[index].value().assert_if_known(|_| {
                let mut actual_bits = vec![];
                h_actual[index].value().map(|x| {
                    for bit in x.to_le_bits() {
                        actual_bits.push(bit)
                    }
                });
                h_expected[index] == u32_from_bits_le(&actual_bits[0..32])
            });
        }

        Ok(())
    }
}

#[test]
fn sha256_one_round_mock_prover() {
    let block = vec![true; 512].try_into().unwrap();
    let circuit = Sha256OneRoundCircuit { block, state: IV };

    let proof = MockProver::run(circuit.k(), &circuit, vec![]).expect("couldn't run mocked prover");
    assert!(proof.verify().is_ok());
}

#[test]
fn sha256_one_round_end_to_end_test() {
    fn test(block: [bool; 512], state: [u32; 8], use_circuit_prover_for_keygen: bool) -> bool {
        let circuit = Sha256OneRoundCircuit { block, state };

        let public_inputs = vec![];

        let k = circuit.k();

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover_for_keygen {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = circuit.without_witnesses();
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        };

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

        let now = std::time::Instant::now();
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
        let proving_time = now.elapsed();

        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let now = std::time::Instant::now();
        let result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok();
        let verifying_time = now.elapsed();

        println!(
            "Proof size: {} bytes; k: {}; proving time: {:.2?}; verifying time: {:.2?}",
            proof.len(),
            k,
            proving_time,
            verifying_time
        );

        result
    }

    //fn negative_test(block: [bool; 512], state: [u32; 8], use_circuit_prover_for_keygen: bool) {
    //    println!("negative test ...");
    //    assert!(!test(block, state, use_circuit_prover_for_keygen));
    //    println!("OK");
    //}

    fn positive_test(block: [bool; 512], state: [u32; 8], use_circuit_prover_for_keygen: bool) {
        println!("positive test ...");
        assert!(test(block, state, use_circuit_prover_for_keygen));
        println!("OK");
    }

    let block = [true; 512];
    let state = IV;
    positive_test(block, state, true);
    //positive_test(block, state, false);
}

//const WORD_BIT_LENGTH: usize = 32;
const WINDOW_BIT_LENGTH: usize = 2;
//const NUM_WINDOWS: usize = (WORD_BIT_LENGTH + WINDOW_BIT_LENGTH - 1) / WINDOW_BIT_LENGTH;

#[derive(Clone)]
struct U32WordModularAddConfig {
    running_sum: RunningSumConfig<Fp, WINDOW_BIT_LENGTH>,
    a: Column<Advice>,
    b: Column<Advice>,
    c_lo: Column<Advice>,
    c_hi: Column<Advice>,
    s_mod_add: Selector,
}

struct U32WordModularAddChip {
    config: U32WordModularAddConfig,
}

impl U32WordModularAddChip {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        z: Column<Advice>,
        q_range_check: Selector,
        a: Column<Advice>,
        b: Column<Advice>,
        s_mod_add: Selector,
        c_lo: Column<Advice>,
        c_hi: Column<Advice>,
    ) -> U32WordModularAddConfig {
        let running_sum =
            RunningSumConfig::<Fp, WINDOW_BIT_LENGTH>::configure(meta, q_range_check, z);

        meta.create_gate("modular add", |meta| {
            let selector = meta.query_selector(s_mod_add);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c_lo = meta.query_advice(c_lo, Rotation::cur());
            let c_hi = meta.query_advice(c_hi, Rotation::cur());

            let c = c_lo + (Expression::Constant(Fp::from(1u64 << 32)) * c_hi);
            [("modular addition", selector * (a + b - c))]
        });

        U32WordModularAddConfig {
            running_sum,
            a,
            b,
            c_lo,
            c_hi,
            s_mod_add,
        }
    }

    fn construct(config: U32WordModularAddConfig) -> Self {
        U32WordModularAddChip { config }
    }

    /*
    fn witness_decompose(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        alpha: Value<Fp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum<Fp>, Error> {
        self.config.running_sum.witness_decompose(
            region,
            offset,
            alpha,
            strict,
            word_num_bits,
            num_windows,
        )
    }

    fn copy_decompose(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        alpha: AssignedCell<Fp, Fp>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum<Fp>, Error> {
        self.config.running_sum.copy_decompose(
            region,
            offset,
            alpha,
            strict,
            word_num_bits,
            num_windows,
        )
    }

    fn range_check(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "range check",
            |mut region| {
                let offset = 0;
                let zs = self.witness_decompose(
                    &mut region,
                    offset,
                    a,
                    true,
                    WORD_BIT_LENGTH,
                    NUM_WINDOWS,
                )?;

                let b = zs[0].clone();

                let offset = offset + NUM_WINDOWS + 1;

                let running_sum = self.copy_decompose(
                    &mut region,
                    offset,
                    b,
                    true,
                    WORD_BIT_LENGTH,
                    NUM_WINDOWS,
                )?;

                Ok(running_sum[0].clone())
            },
        )
    }
*/
    fn modular_add(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: AssignedCell<Fp, Fp>,
        b: AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "modular addition",
            |mut region| {
                self.config.s_mod_add.enable(&mut region, 0)?;

                let a = a.copy_advice(|| "a copy", &mut region, self.config.a, 0)?;

                let b = b.copy_advice(|| "b copy", &mut region, self.config.b, 0)?;

                let c = a
                    .value()
                    .zip(b.value())
                    .map(|(a, b)| {
                        let lhs = a
                            .to_le_bits()
                            .iter()
                            .enumerate()
                            .fold(0u64, |acc, (i, bit)| acc + ((*bit as u64) << i));
                        let rhs = b
                            .to_le_bits()
                            .iter()
                            .enumerate()
                            .fold(0u64, |acc, (i, bit)| acc + ((*bit as u64) << i));

                        let sum = lhs + rhs;
                        let sum_lo = sum & u32::MAX as u64;
                        let sum_hi = sum >> 32;

                        (Fp::from(sum_lo), Fp::from(sum_hi))
                    })
                    .unzip();

                // if a + b overflows, it will be 1, otherwise - 0. Gate definition relies on this information
                region.assign_advice(|| "sum_hi", self.config.c_hi, 0, || c.1)?;

                // output low part of result
                region.assign_advice(|| "sum_lo", self.config.c_lo, 0, || c.0)
            },
        )
    }
}

#[test]
fn load_word_test() {
    #[derive(Clone)]
    struct LoadWordConfig {
        word: [Column<Advice>; 8],
        s_word: Selector,
    }

    struct LoadWordChip {
        config: LoadWordConfig,
    }

    impl LoadWordChip {
        fn configure(
            meta: &mut ConstraintSystem<Fp>,
            word: [Column<Advice>; 8],
            s_word: Selector,
        ) -> LoadWordConfig {
            meta.create_gate(
                "boolean constraint each word's bit",
                |meta: &mut VirtualCells<Fp>| {
                    let s_word = meta.query_selector(s_word);

                    let bits_to_constraint_1 = (0..8)
                        .into_iter()
                        .map(|index| meta.query_advice(word[index], Rotation::cur()))
                        .collect::<Vec<Expression<Fp>>>();

                    let bits_to_constraint_2 = (0..8)
                        .into_iter()
                        .map(|index| meta.query_advice(word[index], Rotation::next()))
                        .collect::<Vec<Expression<Fp>>>();

                    let bits_to_constraint_3 = (0..8)
                        .into_iter()
                        .map(|index| meta.query_advice(word[index], Rotation(2)))
                        .collect::<Vec<Expression<Fp>>>();

                    let bits_to_constraint_4 = (0..8)
                        .into_iter()
                        .map(|index| meta.query_advice(word[index], Rotation(3)))
                        .collect::<Vec<Expression<Fp>>>();

                    let mut bits_to_constraint = [
                        bits_to_constraint_1,
                        bits_to_constraint_2,
                        bits_to_constraint_3,
                        bits_to_constraint_4,
                    ]
                    .concat()
                    .into_iter();

                    Constraints::with_selector(
                        s_word,
                        [
                            ("0", bool_check(bits_to_constraint.next().unwrap())),
                            ("1", bool_check(bits_to_constraint.next().unwrap())),
                            ("2", bool_check(bits_to_constraint.next().unwrap())),
                            ("3", bool_check(bits_to_constraint.next().unwrap())),
                            ("4", bool_check(bits_to_constraint.next().unwrap())),
                            ("5", bool_check(bits_to_constraint.next().unwrap())),
                            ("6", bool_check(bits_to_constraint.next().unwrap())),
                            ("7", bool_check(bits_to_constraint.next().unwrap())),
                            ("8", bool_check(bits_to_constraint.next().unwrap())),
                            ("9", bool_check(bits_to_constraint.next().unwrap())),
                            ("10", bool_check(bits_to_constraint.next().unwrap())),
                            ("11", bool_check(bits_to_constraint.next().unwrap())),
                            ("12", bool_check(bits_to_constraint.next().unwrap())),
                            ("13", bool_check(bits_to_constraint.next().unwrap())),
                            ("14", bool_check(bits_to_constraint.next().unwrap())),
                            ("15", bool_check(bits_to_constraint.next().unwrap())),
                            ("16", bool_check(bits_to_constraint.next().unwrap())),
                            ("17", bool_check(bits_to_constraint.next().unwrap())),
                            ("18", bool_check(bits_to_constraint.next().unwrap())),
                            ("19", bool_check(bits_to_constraint.next().unwrap())),
                            ("20", bool_check(bits_to_constraint.next().unwrap())),
                            ("21", bool_check(bits_to_constraint.next().unwrap())),
                            ("22", bool_check(bits_to_constraint.next().unwrap())),
                            ("23", bool_check(bits_to_constraint.next().unwrap())),
                            ("24", bool_check(bits_to_constraint.next().unwrap())),
                            ("25", bool_check(bits_to_constraint.next().unwrap())),
                            ("26", bool_check(bits_to_constraint.next().unwrap())),
                            ("27", bool_check(bits_to_constraint.next().unwrap())),
                            ("28", bool_check(bits_to_constraint.next().unwrap())),
                            ("29", bool_check(bits_to_constraint.next().unwrap())),
                            ("30", bool_check(bits_to_constraint.next().unwrap())),
                            ("31", bool_check(bits_to_constraint.next().unwrap())),
                        ],
                    )
                },
            );

            LoadWordConfig { word, s_word }
        }

        fn construct(config: LoadWordConfig) -> LoadWordChip {
            LoadWordChip { config }
        }

        fn load_word(
            &self,
            mut layouter: impl Layouter<Fp>,
            word: [bool; WORD_BIT_LEN],
        ) -> Result<Vec<AssignedCell<Bit, Fp>>, Error> {
            layouter.assign_region(
                || "load word",
                |mut region| {
                    self.config.s_word.enable(&mut region, 0)?;

                    let assigned_word_1 = word[..8]
                        .iter()
                        .enumerate()
                        .map(|(index, bit)| {
                            region
                                .assign_advice(
                                    || format!("bit {}", index),
                                    self.config.word[index],
                                    0,
                                    || Value::known(Bit::from(*bit)),
                                )
                                .unwrap()
                        })
                        .collect::<Vec<AssignedCell<Bit, Fp>>>();

                    let assigned_word_2 = word[8..16]
                        .iter()
                        .enumerate()
                        .map(|(index, bit)| {
                            region
                                .assign_advice(
                                    || format!("bit {}", index),
                                    self.config.word[index],
                                    1,
                                    || Value::known(Bit::from(*bit)),
                                )
                                .unwrap()
                        })
                        .collect::<Vec<AssignedCell<Bit, Fp>>>();

                    let assigned_word_3 = word[16..24]
                        .iter()
                        .enumerate()
                        .map(|(index, bit)| {
                            region
                                .assign_advice(
                                    || format!("bit {}", index),
                                    self.config.word[index],
                                    2,
                                    || Value::known(Bit::from(*bit)),
                                )
                                .unwrap()
                        })
                        .collect::<Vec<AssignedCell<Bit, Fp>>>();

                    let assigned_word_4 = word[24..]
                        .iter()
                        .enumerate()
                        .map(|(index, bit)| {
                            region
                                .assign_advice(
                                    || format!("bit {}", index),
                                    self.config.word[index],
                                    3,
                                    || Value::known(Bit::from(*bit)),
                                )
                                .unwrap()
                        })
                        .collect::<Vec<AssignedCell<Bit, Fp>>>();

                    let assigned_word = [
                        assigned_word_1,
                        assigned_word_2,
                        assigned_word_3,
                        assigned_word_4,
                    ]
                    .concat();

                    Ok(assigned_word.try_into().unwrap())
                },
            )
        }
    }

    struct TestCircuit {
        word: [bool; WORD_BIT_LEN],
    }

    impl TestCircuit {
        fn k(&self) -> u32 {
            6
        }
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = LoadWordConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            meta.instance_column(); // unused; only for proper running end-to-end test

            let word = (0..8)
                .into_iter()
                .map(|_| {
                    let word = meta.advice_column();
                    meta.enable_equality(word);
                    word
                })
                .collect::<Vec<Column<Advice>>>();

            let s_word = meta.selector();

            LoadWordChip::configure(meta, word.try_into().unwrap(), s_word)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let chip = LoadWordChip::construct(config);

            chip.load_word(layouter.namespace(|| "1"), self.word.clone())?;

            Ok(())
        }
    }

    let u32_word: u32 = 891347612;

    let circuit = TestCircuit {
        word: u32_to_bits_be(u32_word).try_into().unwrap(),
    };

    let proof =
        MockProver::run(circuit.k(), &circuit, vec![vec![]]).expect("couldn't run mocked prover");
    assert!(proof.verify().is_ok());

    fn test_end_to_end(word: [bool; WORD_BIT_LEN], use_circuit_prover_for_keygen: bool) -> bool {
        let circuit = TestCircuit { word };

        let public_inputs = vec![];

        let k = circuit.k();

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover_for_keygen {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = circuit.without_witnesses();
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        };

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

        let now = std::time::Instant::now();
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
        let proving_time = now.elapsed();

        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let now = std::time::Instant::now();
        let result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok();
        let verifying_time = now.elapsed();

        println!(
            "Proof size: {} bytes; k: {}; proving time: {:.2?}; verifying time: {:.2?}",
            proof.len(),
            k,
            proving_time,
            verifying_time
        );

        result
    }

    //fn negative_test(word: [bool; WORD_BIT_LEN], use_circuit_prover_for_keygen: bool) {
    //    println!("negative test ...");
    //    assert!(!test_end_to_end(word, use_circuit_prover_for_keygen));
    //    println!("OK");
    //}

    fn positive_test(word: [bool; WORD_BIT_LEN], use_circuit_prover_for_keygen: bool) {
        println!("positive test ...");
        assert!(test_end_to_end(word, use_circuit_prover_for_keygen));
        println!("OK");
    }

    let block = [false; WORD_BIT_LEN];

    positive_test(block, true);
    //positive_test(block, false);
}

#[test]
fn test_assigned_word_logical_operations() {
    struct TestCircuit {
        word_a: u32,
        word_b: u32,
        xor: u32,
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = (Sha256Config, AssignedWordLogicalOperationsConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            todo!()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            meta.instance_column();

            let word = (0..8)
                .into_iter()
                .map(|_| {
                    let word = meta.advice_column();
                    meta.enable_equality(word);
                    word
                })
                .collect::<Vec<Column<Advice>>>();

            let s_word = meta.selector();

            let sha256config = Sha256Chip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                s_word,
                None,
                None,
                None,
            );

            let word_2 = (0..8)
                .into_iter()
                .map(|_| {
                    let word = meta.advice_column();
                    meta.enable_equality(word);
                    word
                })
                .collect::<Vec<Column<Advice>>>();

            let word_3 = (0..8)
                .into_iter()
                .map(|_| {
                    let word = meta.advice_column();
                    meta.enable_equality(word);
                    word
                })
                .collect::<Vec<Column<Advice>>>();

            let s_xor = meta.selector();
            let s_and = meta.selector();
            let s_not = meta.selector();

            let word_operations_config = AssignedWordLogicalOperationsChip::configure(
                meta,
                [
                    word[0], word[1], word[2], word[3], word[4], word[5], word[6], word[7],
                ],
                [
                    word_2[0], word_2[1], word_2[2], word_2[3], word_2[4], word_2[5], word_2[6],
                    word_2[7],
                ],
                [
                    word_3[0], word_3[1], word_3[2], word_3[3], word_3[4], word_3[5], word_3[6],
                    word_3[7],
                ],
                s_xor,
                s_and,
                s_not,
            );

            (sha256config, word_operations_config)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let sha256chip = Sha256Chip::construct(config.0);
            let word_operations_chip = AssignedWordLogicalOperationsChip::construct(config.1);

            let word_a_loaded = sha256chip.load_word(
                layouter.namespace(|| "load word_a"),
                Some(u32_to_bits_be(self.word_a).try_into().unwrap()),
            )?;
            let word_b_loaded = sha256chip.load_word(
                layouter.namespace(|| "load word_b"),
                Some(u32_to_bits_be(self.word_b).try_into().unwrap()),
            )?;

            let word_a_loaded = AssignedWord {
                bits: word_a_loaded.into_iter().map(Some).collect(),
            };

            let word_b_loaded = AssignedWord {
                bits: word_b_loaded.into_iter().map(Some).collect(),
            };

            word_operations_chip.xor(
                layouter.namespace(|| "xor word_a and word_b"),
                word_a_loaded,
                word_b_loaded,
                self.xor,
            )?;

            Ok(())
        }
    }

    let circuit = TestCircuit {
        word_a: 50,
        word_b: 75,
        xor: 121,
    };

    let prover =
        MockProver::run(circuit.k(), &circuit, vec![vec![]]).expect("couldn't run mock prover");
    assert!(prover.verify().is_ok());

    fn test_end_to_end(
        word_a: u32,
        word_b: u32,
        word_c: u32,
        use_circuit_prover_for_keygen: bool,
    ) -> bool {
        let circuit = TestCircuit {
            word_a,
            word_b,
            xor: word_c,
        };

        let public_inputs = vec![];

        let k = circuit.k();

        let params: Params<EqAffine> = Params::new(k);

        let pk = if use_circuit_prover_for_keygen {
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        } else {
            let circuit = circuit.without_witnesses();
            let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
            keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail")
        };

        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

        let now = std::time::Instant::now();
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
        let proving_time = now.elapsed();

        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        let now = std::time::Instant::now();
        let result = verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &[&[&public_inputs[..]]],
            &mut transcript,
        )
        .is_ok();
        let verifying_time = now.elapsed();

        println!(
            "Proof size: {} bytes; k: {}; proving time: {:.2?}; verifying time: {:.2?}",
            proof.len(),
            k,
            proving_time,
            verifying_time
        );

        result
    }

    impl TestCircuit {
        fn k(&self) -> u32 {
            5
        }
    }

    assert!(test_end_to_end(50, 75, 121, true));
}

fn u32_to_bits_be(val: u32) -> Vec<bool> {
    (0..32)
        .into_iter()
        .map(|index| (val >> index) & 1 == 1)
        .collect::<Vec<bool>>()
}
