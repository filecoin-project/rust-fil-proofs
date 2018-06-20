use pairing::{Engine, PrimeField, PrimeFieldRepr};

#[derive(Fail, Debug)]
#[fail(display = "Bytes could not be converted to Fr")]
pub struct BadFrBytesError;

pub type Fr32 = [u8];
pub type Fr32Vec = Vec<u8>;
pub type Fr32Ary = [u8; 32];

// Takes a slice of bytes and returns an Fr if byte slice is exactly 32 bytes and does not overflow.
// Otherwise, returns a BadFrBytesError.
pub fn bytes_into_fr<E: Engine>(bytes: &mut &Fr32) -> Result<E::Fr, BadFrBytesError> {
    if bytes.len() != 32 {
        return Err(BadFrBytesError);
    }
    let mut fr_repr = <<<E as Engine>::Fr as PrimeField>::Repr as Default>::default();
    fr_repr.read_le(bytes).map_err(|_| BadFrBytesError)?;

    E::Fr::from_repr(fr_repr).map_err(|_| BadFrBytesError)
}

// Takes an Fr and returns a vector of exactly 32 bytes guaranteed to contain a valid Fr.
pub fn fr_into_bytes<E: Engine>(fr: &E::Fr) -> Fr32Vec {
    let mut out = Vec::new();
    fr.into_repr().write_le(&mut out).unwrap();
    out
}

// Takes a slice of bytes and returns a vector of Fr -- or an error if either bytes is not a multiple of 32 bytes
// or any 32-byte chunk overflows and does not contain a valid Fr.
pub fn bytes_into_frs<E: Engine>(bytes: &mut &[u8]) -> Result<Vec<E::Fr>, BadFrBytesError> {
    bytes
        .chunks(32)
        .map(|ref mut chunk| bytes_into_fr::<E>(chunk))
        .collect()
}

// Takes a slice of Frs and returns a vector of bytes, guaranteed to have a size which is a multiple of 32,
// with every 32-byte chunk representing a valid Fr.
pub fn frs_into_bytes<E: Engine>(frs: &[E::Fr]) -> Fr32Vec {
    frs.iter().flat_map(|fr| fr_into_bytes::<E>(fr)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    fn bytes_fr_test<E: Engine>(bytes: Fr32Ary, expect_success: bool) {
        let mut b = &bytes[..];
        let fr_result = bytes_into_fr::<E>(&mut b);
        if expect_success {
            let f = fr_result.unwrap();
            let b2 = fr_into_bytes::<E>(&f);

            assert_eq!(bytes.to_vec(), b2);
        } else {
            assert!(fr_result.is_err(), "expected a decoding error")
        }
    }
    #[test]
    fn test_bytes_into_fr_into_bytes() {
        bytes_fr_test::<Bls12>(
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
            true,
        );
        bytes_fr_test::<Bls12>(
            // Some bytes fail because they are not in the field.
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 115,
            ],
            false,
        );
        bytes_fr_test::<Bls12>(
            // This is okay.
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 114,
            ],
            true,
        );
        bytes_fr_test::<Bls12>(
            // So is this.
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 236, 115,
            ],
            true,
        );
        bytes_fr_test::<Bls12>(
            // But not this.
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 237, 115,
            ],
            false,
        );
    }

    fn bytes_into_frs_into_bytes_test<E: Engine>(bytes: &Fr32) {
        let mut bytes = bytes.clone();
        let frs = bytes_into_frs::<E>(&mut bytes).unwrap();
        assert!(frs.len() == 3);
        let bytes_back = frs_into_bytes::<E>(&frs);
        assert!(bytes.to_vec() == bytes_back);
    }

    #[test]
    fn test_bytes_into_frs_into_bytes() {
        let bytes = b"012345678901234567890123456789--012345678901234567890123456789--012345678901234567890123456789--";
        bytes_into_frs_into_bytes_test::<Bls12>(&bytes[..]);

        let _short_bytes = b"012345678901234567890123456789--01234567890123456789";
        // This will panic because _short_bytes is not a multiple of 32 bytes.
        // bytes_into_frs_into_bytes_test::<Bls12>(&_short_bytes[..]);
    }
}
