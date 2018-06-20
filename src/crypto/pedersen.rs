use pairing::bls12_381::{Bls12, FrRepr};
use pairing::PrimeFieldRepr;
use sapling_crypto::jubjub::JubjubBls12;
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};

use util::{bits_to_bytes, bytes_into_bits};

lazy_static! {
    static ref JJ_PARAMS: JubjubBls12 = JubjubBls12::new();
}

pub const PEDERSEN_BLOCK_SIZE: usize = 256;

/// Pedersen hashing for inputs that have length mulitple of the block size `256`. Based on pedersen hashes and a Merkle-Damgard construction.
pub fn pedersen_md_no_padding(data: &[u8]) -> Vec<u8> {
    let data_bits = bytes_into_bits(data);

    assert!(
        data_bits.len() >= 2 * PEDERSEN_BLOCK_SIZE,
        "must be at least 2 block sizes long, got {}bits",
        data_bits.len()
    );
    assert_eq!(
        data_bits.len() % PEDERSEN_BLOCK_SIZE,
        0,
        "input must be a multiple of the blocksize"
    );
    let mut chunks = data_bits.chunks(PEDERSEN_BLOCK_SIZE);
    let mut cur: Vec<bool> = chunks.nth(0).unwrap().to_vec();

    for block in chunks {
        cur.extend(block);
        cur = pedersen_compression(&cur);
    }

    bits_to_bytes(&cur)
}

pub fn pedersen_compression(bits: &[bool]) -> Vec<bool> {
    let (x, _) =
        pedersen_hash::<Bls12, _>(Personalization::NoteCommitment, bits.to_vec(), &JJ_PARAMS)
            .into_xy();
    let x: FrRepr = x.into();
    let mut out = Vec::with_capacity(32);
    x.write_le(&mut out).expect("failed to write result hash");

    bytes_into_bits(out.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_pedersen_compression() {
        let x = bytes_into_bits(b"some bytes");
        let hashed = pedersen_compression(&x);
        let expected = vec![
            213, 235, 66, 156, 7, 85, 177, 39, 249, 31, 160, 247, 29, 106, 36, 46, 225, 71, 116,
            23, 1, 89, 82, 149, 45, 189, 27, 189, 144, 98, 23, 98,
        ];
        assert_eq!(expected, bits_to_bytes(&hashed));
    }

    #[test]
    fn test_pedersen_md_no_padding() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for i in 2..6 {
            let x: Vec<u8> = (0..i * 32).map(|_| rng.gen()).collect();
            let hashed = pedersen_md_no_padding(x.as_slice());

            assert_eq!(hashed.len(), 32);
        }
    }
}
