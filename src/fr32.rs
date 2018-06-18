use pairing::bls12_381::Bls12;
use pairing::{Engine, PrimeField, PrimeFieldRepr};
use std::{self, error, fmt};

#[derive(Debug, Clone)]
pub struct BadFrBytesError;

pub type Fr32 = [u8];
type Fr32Vec = Vec<u8>;
type Fr32Ary = [u8; 32];

impl fmt::Display for BadFrBytesError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "bytes could not be converted to Fr")
    }
}

impl std::error::Error for BadFrBytesError {
    fn description(&self) -> &str {
        "bytes could not be converted to Fr"
    }

    fn cause(&self) -> Option<&std::error::Error> {
        // Generic error, underlying cause isn't tracked.
        None
    }
}

pub fn make_fr32(bytes: &[u8]) -> Result<&Fr32, BadFrBytesError> {
    if bytes.len() != 32 {
        return Err(BadFrBytesError);
    }
    Ok(bytes)
}

pub fn bytes_into_fr<E: Engine>(bytes: &mut &Fr32) -> Result<E::Fr, BadFrBytesError> {
    if bytes.len() != 32 {
        return Err(BadFrBytesError);
    }
    let mut fr_repr = <<<E as Engine>::Fr as PrimeField>::Repr as Default>::default();
    fr_repr.read_le(bytes).map_err(|_| BadFrBytesError)?;

    E::Fr::from_repr(fr_repr).map_err(|_| BadFrBytesError)
}

pub fn fr_into_bytes<E: Engine>(fr: &E::Fr) -> Fr32Vec {
    let mut out = Vec::new();
    fr.into_repr().write_le(&mut out).unwrap();
    out
}

pub fn bytes_into_frs<E: Engine>(bytes: &mut &[u8]) -> Result<Vec<E::Fr>, BadFrBytesError> {
    let mut result = Vec::new();
    for mut chunk in bytes.chunks(32) {
        let fr = bytes_into_fr::<E>(&mut chunk)?;
        result.push(fr);
    }
    Ok(result)
}

pub fn frs_into_bytes<E: Engine>(frs: &[E::Fr]) -> Fr32Vec {
    frs.iter().flat_map(|fr| fr_into_bytes::<E>(fr)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
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
