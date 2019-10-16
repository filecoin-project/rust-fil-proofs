use ff::PrimeFieldRepr;
use fil_sapling_crypto::jubjub::JubjubBls12;
use fil_sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use paired::bls12_381::{Bls12, Fr, FrRepr};

use crate::fr32::bytes_into_frs;
use crate::settings;

lazy_static! {
    pub static ref JJ_PARAMS: JubjubBls12 = JubjubBls12::new_with_window_size(
        settings::SETTINGS
            .lock()
            .unwrap()
            .pedersen_hash_exp_window_size
    );
}

pub const PEDERSEN_BLOCK_SIZE: usize = 256;
pub const PEDERSEN_BLOCK_BYTES: usize = PEDERSEN_BLOCK_SIZE / 8;

pub fn pedersen(data: &[u8]) -> Fr {
    pedersen_hash::<Bls12, _>(Personalization::None, Bits::new(data), &JJ_PARAMS)
        .into_xy()
        .0
}

#[derive(Debug, Clone)]
enum VecOrSingle<T> {
    Vec(Vec<T>),
    Single(T),
}

impl<T> VecOrSingle<T> {
    pub fn len(&self) -> usize {
        match self {
            VecOrSingle::Vec(ref list) => list.len(),
            VecOrSingle::Single(_) => 1,
        }
    }
}

/// Creates an iterator over the byte slices in little endian format.
#[derive(Debug, Clone)]
pub struct Bits<'a> {
    parts: VecOrSingle<&'a [u8]>,
    position_byte: usize,
    position_bit: u8,
    position_part: usize,
    done: bool,
}

impl<'a> Bits<'a> {
    pub fn new(parts: &'a [u8]) -> Self {
        Bits {
            parts: VecOrSingle::Single(parts),
            position_byte: 0,
            position_bit: 0,
            position_part: 0,
            done: false,
        }
    }

    pub fn new_vec(parts: Vec<&'a [u8]>) -> Self {
        Bits {
            parts: VecOrSingle::Vec(parts),
            position_byte: 0,
            position_bit: 0,
            position_part: 0,
            done: false,
        }
    }

    fn get_part(&self, part: usize) -> &'a [u8] {
        match self.parts {
            VecOrSingle::Vec(ref parts) => parts[part],
            VecOrSingle::Single(part) => part,
        }
    }

    /// Increments the inner positions by 1 bit.
    fn inc(&mut self) {
        if self.position_bit < 7 {
            self.position_bit += 1;
            return;
        }

        self.position_bit = 0;
        if self.position_byte + 1 < self.get_part(self.position_part).len() {
            self.position_byte += 1;
            return;
        }

        self.position_byte = 0;
        if self.position_part + 1 < self.parts.len() {
            self.position_part += 1;
            return;
        }

        self.done = true;
    }

    fn ref_take<'b>(&'b mut self, take: usize) -> BitsTake<'b, 'a> {
        BitsTake::new(self, take)
    }
}

#[derive(Debug)]
struct BitsTake<'a, 'b: 'a> {
    iter: &'a mut Bits<'b>,
    take: usize,
}

impl<'a, 'b> BitsTake<'a, 'b> {
    pub fn new(iter: &'a mut Bits<'b>, take: usize) -> Self {
        BitsTake { iter, take }
    }
}

impl<'a, 'b> ExactSizeIterator for BitsTake<'a, 'b> {
    fn len(&self) -> usize {
        self.take
    }
}

impl<'a, 'b> std::iter::FusedIterator for BitsTake<'a, 'b> {}

impl<'a, 'b> Iterator for BitsTake<'a, 'b> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.take == 0 {
            return None;
        }

        self.take -= 1;
        self.iter.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.len();
        (size, Some(size))
    }
}

impl<'a> ExactSizeIterator for Bits<'a> {
    fn len(&self) -> usize {
        let byte_len: usize = match self.parts {
            VecOrSingle::Vec(ref parts) => parts.iter().map(|part| part.len()).sum(),
            VecOrSingle::Single(ref part) => part.len(),
        };

        byte_len * 8
    }
}

impl<'a> std::iter::FusedIterator for Bits<'a> {}

impl<'a> Iterator for Bits<'a> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let byte = self.get_part(self.position_part)[self.position_byte];

        let res = (byte >> self.position_bit) & 1u8 == 1u8;
        self.inc();

        Some(res)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.len();
        (size, Some(size))
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

/// Pedersen hashing for inputs that have length mulitple of the block size `256`. Based on pedersen hashes and a Merkle-Damgard construction.
pub fn pedersen_md_no_padding(data: &[u8]) -> Fr {
    pedersen_md_no_padding_bits(Bits::new(data))
}

pub fn pedersen_md_no_padding_bits(mut data: Bits) -> Fr {
    assert!(
        data.len() >= 2 * PEDERSEN_BLOCK_BYTES,
        "must be at least 2 block sizes long, got {}bits",
        data.len()
    );
    assert_eq!(
        data.len() % PEDERSEN_BLOCK_BYTES,
        0,
        "input must be a multiple of the blocksize"
    );

    let block_count = data.len() / PEDERSEN_BLOCK_SIZE;

    let mut cur = Vec::with_capacity(PEDERSEN_BLOCK_SIZE);

    // hash the first two blocks
    let first = pedersen_compression_bits(data.ref_take(2 * PEDERSEN_BLOCK_SIZE));
    first
        .write_le(&mut cur)
        .expect("failed to write result hash");

    for _ in 2..block_count {
        let r = data.ref_take(PEDERSEN_BLOCK_SIZE);
        let x = pedersen_compression_bits(Bits::new(&cur).chain(r));

        cur.truncate(0);
        x.write_le(&mut cur).expect("failed to write result hash");
    }

    let frs = bytes_into_frs::<Bls12>(&cur).expect("pedersen must generate valid fr elements");
    assert_eq!(frs.len(), 1);
    frs[0]
}

fn pedersen_compression_bits<T>(bits: T) -> FrRepr
where
    T: IntoIterator<Item = bool>,
{
    let (x, _) = pedersen_hash::<Bls12, _>(Personalization::None, bits, &JJ_PARAMS).into_xy();
    x.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::bytes_into_bits;
    use bitvec::{self, BitVec};
    use ff::Field;
    use paired::bls12_381::Fr;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_bit_vec_le() {
        let bytes = b"ABC";
        let bits = bytes_into_bits(bytes);

        let mut bits2 = core::iter::repeat(false)
            .take(bits.len())
            .collect::<BitVec<bitvec::LittleEndian, u8>>();

        bits2.as_mut()[0..bytes.len()].copy_from_slice(&bytes[..]);

        assert_eq!(bits, bits2.iter().collect::<Vec<bool>>());
    }

    #[test]
    fn test_pedersen_compression() {
        let bytes = Bits::new(b"some bytes");

        let x = pedersen_compression_bits(bytes);
        let mut data = Vec::new();
        x.write_le(&mut data).unwrap();

        let expected = vec![
            237, 70, 41, 231, 39, 180, 131, 120, 36, 36, 119, 199, 200, 225, 153, 242, 106, 116,
            70, 9, 12, 249, 169, 84, 105, 38, 225, 115, 165, 188, 98, 25,
        ];
        assert_eq!(expected, data);
    }

    #[test]
    fn test_pedersen_md_no_padding() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 2..5 {
            let x: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();
            let hashed = pedersen_md_no_padding(x.as_slice());
            assert_ne!(hashed, Fr::zero());
        }
    }

    #[test]
    fn test_bits() {
        let bytes = b"hello";
        let bits = bytes_into_bits(bytes);

        let bits_iter = Bits::new(bytes);
        let bits_iter_collected: Vec<bool> = bits_iter.collect();

        assert_eq!(bits, bits_iter_collected);

        let bytes = b"hello world these are some bytes";
        let bits = bytes_into_bits(bytes);

        let bits_iter = Bits::new_vec(vec![b"hello ", b"world", b" these are some bytes"]);
        assert_eq!(bits_iter.len(), bits.len());

        let bits_iter_collected: Vec<bool> = bits_iter.collect();

        assert_eq!(bits, bits_iter_collected);
    }

    #[test]
    fn test_bits_take() {
        let bytes = b"hello world these are some bytes";
        let bits = bytes_into_bits(bytes);

        let mut bits_iter = Bits::new_vec(vec![b"hello ", b"world", b" these are some bytes"]);
        assert_eq!(bits_iter.len(), bits.len());

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
}
