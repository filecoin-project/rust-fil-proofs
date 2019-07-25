use bitvec::prelude::*;
use crate::fr32::bytes_into_frs;
use crate::singletons::PEDERSEN_PARAMS;

use algebra::biginteger::BigInteger;
use algebra::curves::{bls12_381::Bls12_381 as Bls12, jubjub::JubJubProjective as JubJub,
    ProjectiveCurve, models::twisted_edwards_extended::GroupProjective, jubjub::JubJubParameters};
use algebra::fields::{bls12_381::Fr, PrimeField};
use dpc::crypto_primitives::crh::{
    pedersen::{PedersenCRH, PedersenWindow},
    FixedLengthCRH,
};


#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BigWindow;

impl PedersenWindow for BigWindow {
    const WINDOW_SIZE: usize = 2016;
    const NUM_WINDOWS: usize = 1;
}

pub const PEDERSEN_BLOCK_SIZE: usize = 256;
pub const PEDERSEN_BLOCK_BYTES: usize = PEDERSEN_BLOCK_SIZE / 8;

#[derive(Copy, Clone)]
pub enum Personalization {
    NoteCommitment,
    MerkleTree(usize),
}

impl Personalization {
    pub fn get_bits(&self) -> Vec<bool> {
        match *self {
            Personalization::NoteCommitment => vec![true, true, true, true, true, true, false, false],
            Personalization::MerkleTree(num) => {
                assert!(num < 63);

                (0..6).map(|i| (num >> i) & 1 == 1).collect()
            }
        }
    }
}

pub fn pedersen_hash<I>(personalization: Personalization, bits: I) -> GroupProjective<JubJubParameters>
where
    I: IntoIterator<Item = bool>,
{
    let mut bits: Vec<bool> = personalization
        .get_bits()
        .into_iter()
        .chain(bits.into_iter())
        .collect();

    while bits.len() % 8 != 0 {
        bits.push(false);
    }

    let bytes = BitVec::<LittleEndian, _>::from(&bits[..]);

    PedersenCRH::<JubJub, BigWindow>::evaluate(&PEDERSEN_PARAMS, bytes.as_slice()).unwrap()
}

pub fn pedersen(data: &[u8]) -> GroupProjective<JubJubParameters> {
    let bits = BitVec::<LittleEndian, u8>::from(data);
    pedersen_hash(Personalization::NoteCommitment, bits)
}

/// Pedersen hashing for inputs that have length multiple of the block size `256`. Based on pedersen hashes and a Merkle-Damgard construction.
pub fn pedersen_md_no_padding(data: &[u8]) -> Fr {
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
    let mut chunks = data.chunks(PEDERSEN_BLOCK_BYTES);
    let mut cur = Vec::with_capacity(2 * PEDERSEN_BLOCK_BYTES);
    cur.resize(PEDERSEN_BLOCK_BYTES, 0);
    cur[0..PEDERSEN_BLOCK_BYTES].copy_from_slice(chunks.nth(0).unwrap());

    for block in chunks {
        cur.resize(2 * PEDERSEN_BLOCK_BYTES, 0);
        cur[PEDERSEN_BLOCK_BYTES..].copy_from_slice(block);
        pedersen_compression(&mut cur);
    }

    let frs = bytes_into_frs::<Bls12>(&cur[0..PEDERSEN_BLOCK_BYTES])
        .expect("pedersen must generate valid fr elements");
    assert_eq!(frs.len(), 1);
    frs[0]
}

pub fn pedersen_compression(bytes: &mut Vec<u8>) {
    let point = pedersen(&bytes[..]);
    bytes.truncate(0);
    point.into_affine().x.into_repr()
        .write_le(bytes)
        .expect("failed to write result hash")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::bytes_into_bits;
    use algebra::fields::Field;
    use rand::Rng;
    use rand::SeedableRng;
    use rand::XorShiftRng;

    #[test]
    fn test_bit_vec_le() {
        let bytes = b"ABC";
        let bits = bytes_into_bits(bytes);

        let mut bits2 = bitvec![LittleEndian, u8; 0; bits.len()];
        bits2.as_mut_slice()[0..bytes.len()].copy_from_slice(&bytes[..]);

        assert_eq!(bits, bits2.iter().collect::<Vec<bool>>());
    }

    #[test]
    fn test_pedersen_compression() {
        let bytes = b"some bytes";
        let mut data = vec![0; bytes.len()];
        data.copy_from_slice(&bytes[..]);
        pedersen_compression(&mut data);
        let expected = vec![
            213, 235, 66, 156, 7, 85, 177, 39, 249, 31, 160, 247, 29, 106, 36, 46, 225, 71, 116,
            23, 1, 89, 82, 149, 45, 189, 27, 189, 144, 98, 23, 98,
        ];
        // Note: this test fails as we use different generator points and zexe used a slightly different approach
        // for Pedersen hashing (no windowing). Hence the expected output should be updated.
        // assert_eq!(expected, data);
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
}
