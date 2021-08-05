use anyhow::{ensure, Result};
use blstrs::Scalar as Fr;
use ff::PrimeField;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Bytes could not be converted to Fr")]
    BadFrBytes,
}

/// Contains one or more 32-byte chunks whose little-endian values represent Frs.
/// Invariants:
/// - Value of each 32-byte chunks MUST represent valid Frs.
/// - Total length must be a multiple of 32.
/// That is to say: each 32-byte chunk taken alone must be a valid Fr32.
pub type Fr32Vec = Vec<u8>;

/// Array whose little-endian value represents an Fr.
/// Invariants:
/// - Value MUST represent a valid Fr.
pub type Fr32Ary = [u8; 32];

/// Takes a slice of bytes (little-endian, non-Montgomery form) and returns an Fr if byte slice is
/// exactly 32 bytes and does not overflow. Otherwise, returns a BadFrBytesError.
pub fn bytes_into_fr(le_bytes: &[u8]) -> Result<Fr> {
    ensure!(le_bytes.len() == 32, Error::BadFrBytes);
    let mut repr = [0u8; 32];
    repr.copy_from_slice(le_bytes);
    Fr::from_repr_vartime(repr).ok_or_else(|| Error::BadFrBytes.into())
}

/// Converts a slice of 32 bytes (little-endian, non-Montgomery form) into an `Fr::Repr` by
/// zeroing the most signficant two bits of `le_bytes`.
#[inline]
pub fn bytes_into_fr_repr_safe(le_bytes: &[u8]) -> <Fr as PrimeField>::Repr {
    debug_assert!(le_bytes.len() == 32);
    let mut repr = [0u8; 32];
    repr.copy_from_slice(le_bytes);
    repr[31] &= 0b0011_1111;
    repr
}

/// Takes an Fr and returns a vector of exactly 32 bytes guaranteed to contain a valid Fr.
#[inline]
pub fn fr_into_bytes(fr: &Fr) -> Fr32Vec {
    fr.to_repr().to_vec()
}

#[inline]
pub fn u64_into_fr(n: u64) -> Fr {
    Fr::from(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_fr_test(bytes: Fr32Ary, expect_success: bool) {
        let b = &bytes[..];
        let fr_result = bytes_into_fr(&b);
        if expect_success {
            let f = fr_result.expect("Failed to convert bytes to `Fr`");
            let b2 = fr_into_bytes(&f);
            assert_eq!(bytes.to_vec(), b2);
        } else {
            assert!(fr_result.is_err(), "expected a decoding error")
        }
    }

    #[test]
    fn test_bytes_into_fr_into_bytes() {
        bytes_fr_test(
            [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
            true,
        );
        bytes_fr_test(
            // Some bytes fail because they are not in the field.
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 115,
            ],
            false,
        );
        bytes_fr_test(
            // This is okay.
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 114,
            ],
            true,
        );
        bytes_fr_test(
            // So is this.
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 236, 115,
            ],
            true,
        );
        bytes_fr_test(
            // But not this.
            [
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 237, 115,
            ],
            false,
        );
    }
}
