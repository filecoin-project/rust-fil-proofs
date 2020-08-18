use anyhow::{ensure, Context};
use ff::PrimeFieldRepr;
use fil_sapling_crypto::jubjub::JubjubBls12;
use lazy_static::lazy_static;
use paired::bls12_381::{Fr, FrRepr};

use crate::error::Result;
use crate::fr32::bytes_into_frs;
use crate::hasher::pedersen::pedersen_hash;
use crate::settings;

lazy_static! {
    pub static ref JJ_PARAMS: JubjubBls12 = JubjubBls12::new_with_window_size(
        settings::SETTINGS
            .lock()
            .expect("settings lock failure")
            .pedersen_hash_exp_window_size
    );
}

pub const PEDERSEN_BLOCK_SIZE: usize = 256;
pub const PEDERSEN_BLOCK_BYTES: usize = PEDERSEN_BLOCK_SIZE / 8;

pub fn pedersen(data: &[u8]) -> Fr {
    pedersen_bits(Bits::new(data))
}

pub fn pedersen_bits<'a, S: Iterator<Item = &'a [u8]>>(data: Bits<&'a [u8], S>) -> Fr {
    let digest = pedersen_hash(data);
    digest.into_xy().0
}

/// Pedersen hashing for inputs that have length mulitple of the block size `256`. Based on pedersen hashes and a Merkle-Damgard construction.
pub fn pedersen_md_no_padding(data: &[u8]) -> Fr {
    pedersen_md_no_padding_bits(Bits::new(data))
}

pub fn pedersen_md_no_padding_bits<T: AsRef<[u8]>, S: Iterator<Item = T>>(
    mut data: Bits<T, S>,
) -> Fr {
    let mut cur = Vec::with_capacity(PEDERSEN_BLOCK_SIZE);

    // hash the first two blocks
    let first = pedersen_compression_bits(data.ref_take(2 * PEDERSEN_BLOCK_SIZE));
    first
        .write_le(&mut cur)
        .expect("failed to write result hash");

    while !data.is_done() {
        let r = data.ref_take(PEDERSEN_BLOCK_SIZE);
        let x = pedersen_compression_bits(Bits::new(&cur).chain(r));

        cur.truncate(0);
        x.write_le(&mut cur).expect("failed to write result hash");
    }

    let frs = bytes_into_frs(&cur).expect("pedersen must generate valid fr elements");
    assert_eq!(frs.len(), 1);
    frs[0]
}

fn pedersen_compression_bits<T>(bits: T) -> FrRepr
where
    T: IntoIterator<Item = bool>,
{
    let digest = pedersen_hash(bits);
    digest.into_xy().0.into()
}

#[derive(Debug, Clone)]
pub struct Hasher {
    curr: Option<[u8; 32]>,
}

impl Hasher {
    pub fn new(data: &[u8]) -> Result<Self> {
        ensure!(data.len() == 32, "Data must be 32 bytes.");
        let mut curr = [0u8; 32];
        curr.copy_from_slice(data);

        Ok(Hasher { curr: Some(curr) })
    }

    pub fn new_empty() -> Self {
        Hasher { curr: None }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        ensure!(data.len() == 32, "Data must be 32 bytes.");

        if let Some(ref mut curr) = self.curr {
            let source = [curr, data];
            let data = Bits::new_many(source.iter());
            let x = pedersen_compression_bits(data);
            x.write_le(std::io::Cursor::new(&mut curr[..]))
                .context("failed to write result")?;
        } else {
            let data = Bits::new(data);
            let x = pedersen_compression_bits(data);
            let mut curr = [0u8; 32];
            x.write_le(std::io::Cursor::new(&mut curr[..]))
                .context("failed to write result")?;
            self.curr = Some(curr);
        }

        Ok(())
    }

    pub fn finalize_bytes(self) -> [u8; 32] {
        let Hasher { curr } = self;
        curr.expect("missed init")
    }

    pub fn finalize(self) -> Result<Fr> {
        let frs = bytes_into_frs(&self.curr.expect("missed init"))
            .context("pedersen must generate valid fr elements")?;
        ensure!(frs.len() == 1, "There must be a single fr element.");
        Ok(frs[0])
    }
}

/// Creates an iterator over the byte slices in little endian format.
#[derive(Debug, Clone)]
pub struct Bits<K: AsRef<[u8]>, S: Iterator<Item = K>> {
    /// The individual parts that make up the data that is being iterated over.
    parts: ManyOrSingle<K, S>,
    /// How many bytes we are into the `current_part`
    position_byte: usize,
    /// How many bits we are into the `current_byte`.
    position_bit: u8,
    /// The current part we are reading from.
    current_part: Option<K>,
    /// Track the first iteration.
    first: bool,
    /// Are we done yet?
    done: bool,
}

/// Abstraction over either an iterator or a single element.
#[derive(Debug, Clone)]
enum ManyOrSingle<T, S = <Vec<T> as IntoIterator>::IntoIter>
where
    S: Iterator<Item = T>,
{
    Many(S),
    Single(Option<T>),
}

impl<T: AsRef<[u8]>> Bits<T, <Vec<T> as IntoIterator>::IntoIter> {
    pub fn new(parts: T) -> Self {
        Bits {
            parts: ManyOrSingle::<T, <Vec<T> as IntoIterator>::IntoIter>::Single(Some(parts)),
            position_byte: 0,
            position_bit: 0,
            current_part: None,
            first: true,
            done: false,
        }
    }
}

impl<T: AsRef<[u8]>, S: Iterator<Item = T>> Bits<T, S> {
    pub fn new_many(parts: S) -> Self {
        Bits {
            parts: ManyOrSingle::Many(parts),
            position_byte: 0,
            position_bit: 0,
            current_part: None,
            first: true,
            done: false,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    fn inc_part(&mut self) {
        self.current_part = match self.parts {
            ManyOrSingle::Many(ref mut parts) => {
                if self.first {
                    self.first = false;
                }
                parts.next()
            }
            ManyOrSingle::Single(ref mut part) => {
                if self.first {
                    self.first = false;
                    part.take()
                } else {
                    None
                }
            }
        }
    }

    /// Increments the inner positions by 1 bit.
    fn inc(&mut self) {
        if self.position_bit < 7 {
            self.position_bit += 1;
            return;
        }

        self.position_bit = 0;
        if let Some(ref part) = self.current_part {
            if self.position_byte + 1 < part.as_ref().len() {
                self.position_byte += 1;
                return;
            }
        }

        self.inc_part();
        self.position_byte = 0;
        self.done = self.current_part.is_none();
    }

    fn ref_take(&mut self, take: usize) -> BitsTake<'_, T, S> {
        BitsTake::new(self, take)
    }
}

#[derive(Debug)]
struct BitsTake<'a, T: AsRef<[u8]>, S: Iterator<Item = T>> {
    iter: &'a mut Bits<T, S>,
    take: usize,
}

impl<'a, T: AsRef<[u8]>, S: Iterator<Item = T>> BitsTake<'a, T, S> {
    pub fn new(iter: &'a mut Bits<T, S>, take: usize) -> Self {
        BitsTake { iter, take }
    }
}

impl<'a, T: AsRef<[u8]>, S: Iterator<Item = T> + std::iter::FusedIterator> std::iter::FusedIterator
    for BitsTake<'a, T, S>
{
}

impl<'a, T: AsRef<[u8]>, S: Iterator<Item = T>> Iterator for BitsTake<'a, T, S> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.take == 0 {
            return None;
        }

        self.take -= 1;
        self.iter.next()
    }
}

impl<T: AsRef<[u8]>, S: Iterator<Item = T> + std::iter::FusedIterator> std::iter::FusedIterator
    for Bits<T, S>
{
}

impl<T: AsRef<[u8]>, S: Iterator<Item = T>> Iterator for Bits<T, S> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.first {
            // first time
            self.inc_part();
        }

        let byte = match self.current_part {
            Some(ref part) => part.as_ref()[self.position_byte],
            None => {
                self.done = true;
                return None;
            }
        };

        let res = (byte >> self.position_bit) & 1u8 == 1u8;
        self.inc();

        Some(res)
    }

    // optimized nth method so we can use it to skip forward easily
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        for _ in 0..n {
            // TODO: implement optimized inc for n bits.
            self.inc();
        }
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::bytes_into_bits;
    use bitvec::{bitvec, order::Lsb0};
    use ff::Field;
    use paired::bls12_381::Fr;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_bit_vec_le() {
        let bytes = b"ABC";
        let bits = bytes_into_bits(bytes);

        let mut bits2 = bitvec![Lsb0, u8; 0; bits.len()];
        bits2.as_mut_slice()[0..bytes.len()].copy_from_slice(&bytes[..]);

        assert_eq!(bits, bits2.iter().copied().collect::<Vec<bool>>());
    }

    #[test]
    fn test_pedersen_compression() {
        let bytes = Bits::new(b"some bytes");

        let x = pedersen_compression_bits(bytes);
        let mut data = Vec::new();
        x.write_le(&mut data).expect("write_le failure");

        let expected = vec![
            237, 70, 41, 231, 39, 180, 131, 120, 36, 36, 119, 199, 200, 225, 153, 242, 106, 116,
            70, 9, 12, 249, 169, 84, 105, 38, 225, 115, 165, 188, 98, 25,
        ];
        assert_eq!(expected, data);
    }

    #[test]
    fn test_pedersen_md_no_padding() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for i in 2..5 {
            let x: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();
            let hashed = pedersen_md_no_padding(x.as_slice());
            assert_ne!(hashed, Fr::zero());
        }
    }

    #[test]
    fn test_bits_collect() {
        let bytes = b"hello";
        let bits = bytes_into_bits(bytes);

        let bits_iter = Bits::new(bytes);
        let bits_iter_collected: Vec<bool> = bits_iter.collect();

        assert_eq!(bits, bits_iter_collected);

        let bytes = b"hello world these are some bytes";
        let bits = bytes_into_bits(bytes);

        let parts: Vec<&[u8]> = vec![b"hello ", b"world", b" these are some bytes"];
        let bits_iter = Bits::new_many(parts.into_iter());

        let bits_iter_collected: Vec<bool> = bits_iter.collect();

        assert_eq!(bits, bits_iter_collected);
    }

    #[test]
    fn test_bits_take() {
        let bytes = b"hello world these are some bytes";
        let bits = bytes_into_bits(bytes);

        let parts: Vec<&[u8]> = vec![b"hello ", b"world", b" these are some bytes"];
        let mut bits_iter = Bits::new_many(parts.into_iter());

        let bits_collected: Vec<bool> = vec![
            bits_iter.ref_take(8).collect::<Vec<bool>>(),
            bits_iter.ref_take(8).collect::<Vec<bool>>(),
            bits_iter.ref_take(bits.len() - 16).collect::<Vec<bool>>(),
        ]
        .into_iter()
        .flatten()
        .collect();

        assert_eq!(bits, bits_collected);
    }

    #[test]
    fn test_pedersen_hasher_update() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 2..5 {
            let x: Vec<Vec<u8>> = (0..5)
                .map(|_| (0..32).map(|_| rng.gen()).collect())
                .collect();
            let flat: Vec<u8> = x.iter().flatten().copied().collect();
            let hashed = pedersen_md_no_padding(&flat);

            let mut hasher = Hasher::new(&x[0]).expect("hasher new failure");
            for val in x.iter().skip(1).take(4) {
                hasher.update(&val).expect("hasher update failure");
            }

            let hasher_final = hasher.finalize().expect("hasher finalize failure");

            assert_eq!(hashed, hasher_final);
        }
    }
}
