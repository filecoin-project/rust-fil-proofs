use bit_vec::BitVec;
use pairing::bls12_381::{Bls12, FrRepr};
use pairing::PrimeFieldRepr;
use sapling_crypto::jubjub::JubjubBls12;
use sapling_crypto::pedersen_hash::{pedersen_hash, Personalization};
use std::slice;

lazy_static! {
    static ref JJ_PARAMS: JubjubBls12 = JubjubBls12::new();
}

pub fn pedersen_jubjub_internal(_height: i32, bytes: &[u8]) -> Vec<u8> {
    // TODO: let personalization vary by height.
    let personalization = Personalization::NoteCommitment;
    let pt = pedersen_hash::<Bls12, _>(personalization, BitVec::from_bytes(bytes), &JJ_PARAMS);
    let x: FrRepr = pt.into_xy().0.into();
    let mut out = Vec::with_capacity(32);
    x.write_le(&mut out).expect("failed to write result hash");

    out
}

#[no_mangle]
pub extern "C" fn pedersen_jubjub(height: i32, size: usize, bytes: *mut u8) -> *mut u8 {
    let byte_slice = unsafe { slice::from_raw_parts(bytes, size) };
    let mut x = pedersen_jubjub_internal(height, byte_slice);

    x.as_mut_ptr()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pedersen() {
        let x = b"some bytes";
        let hashed = pedersen_jubjub_internal(0, x);
        let expected = vec![
            108, 164, 213, 82, 12, 14, 65, 228, 59, 219, 147, 122, 119, 177, 0, 1, 93, 87, 127,
            178, 192, 144, 2, 91, 113, 203, 31, 99, 205, 169, 184, 97,
        ];
        assert_eq!(expected, hashed);
    }
}
