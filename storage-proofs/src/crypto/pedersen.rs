use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::PrimeFieldRepr;
use sapling_crypto::jubjub::JubjubBls12;
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

use crate::fr32::bytes_into_frs;

use bitvec::{self, BitVec};

lazy_static! {
    pub static ref JJ_PARAMS: JubjubBls12 = JubjubBls12::new();
}

pub const PEDERSEN_BLOCK_SIZE: usize = 256;
pub const PEDERSEN_BLOCK_BYTES: usize = PEDERSEN_BLOCK_SIZE / 8;

pub fn pedersen(data: &[u8]) -> Fr {
    pedersen_hash::<Bls12, _>(
        Personalization::NoteCommitment,
        BitVec::<bitvec::LittleEndian, u8>::from(data)
            .iter()
            .take(data.len() * 8),
        &JJ_PARAMS,
    )
    .into_xy()
    .0
}

/// Pedersen hashing for inputs that have length mulitple of the block size `256`. Based on pedersen hashes and a Merkle-Damgard construction.
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
    let bits = BitVec::<bitvec::LittleEndian, u8>::from(&bytes[..]);
    let (x, _) = pedersen_hash::<Bls12, _>(
        Personalization::NoteCommitment,
        bits.iter().take(bytes.len() * 8),
        &JJ_PARAMS,
    )
    .into_xy();
    let x: FrRepr = x.into();

    bytes.truncate(0);
    x.write_le(bytes).expect("failed to write result hash");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::bytes_into_bits;
    use pairing::bls12_381::Fr;
    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    #[test]
    fn test_bit_vec_le() {
        let bytes = b"ABC";
        let bits = bytes_into_bits(bytes);

        let mut bits2 = bitvec![LittleEndian, u8; 0; bits.len()];
        bits2.as_mut()[0..bytes.len()].copy_from_slice(&bytes[..]);

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
}
