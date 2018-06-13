use pairing::bls12_381::{Bls12, FrRepr};
use pairing::PrimeFieldRepr;
use sapling_crypto::jubjub::JubjubBls12;
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use std::slice;

use util::bytes_into_bits;

lazy_static! {
    static ref JJ_PARAMS: JubjubBls12 = JubjubBls12::new();
}

pub fn pedersen_jubjub_internal(_height: i32, bytes: &[u8]) -> Vec<u8> {
    // TODO: let personalization vary by height.
    let personalization = Personalization::NoteCommitment;
    let pt = pedersen_hash::<Bls12, _>(personalization, bytes_into_bits(bytes), &JJ_PARAMS);
    let x: FrRepr = pt.into_xy().0.into();
    let mut out = Vec::with_capacity(32);
    x.write_le(&mut out).expect("failed to write result hash");

    out
}

#[no_mangle]
pub unsafe extern "C" fn pedersen_jubjub(height: i32, size: usize, bytes: *mut u8) -> *mut u8 {
    let byte_slice = slice::from_raw_parts(bytes, size);
    let mut x = pedersen_jubjub_internal(height, byte_slice);

    x.as_mut_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen() {
        let x = b"some bytes";
        let hashed = pedersen_jubjub_internal(0, x);
        let expected = vec![
            213, 235, 66, 156, 7, 85, 177, 39, 249, 31, 160, 247, 29, 106, 36, 46, 225, 71, 116,
            23, 1, 89, 82, 149, 45, 189, 27, 189, 144, 98, 23, 98,
        ];
        assert_eq!(expected, hashed);
    }
}
