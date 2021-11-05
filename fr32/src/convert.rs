#[cfg(any(feature = "pairing", feature = "blst"))]
use anyhow::Result;
use bellperson::bls::{Fr, FrRepr};
use byteorder::{ByteOrder, LittleEndian};
use ff::PrimeField;
#[cfg(feature = "pairing")]
use ff::PrimeFieldRepr;

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

/// Takes a slice of bytes and returns an Fr if byte slice is exactly 32 bytes and does not overflow.
/// Otherwise, returns a BadFrBytesError.
#[cfg(feature = "pairing")]
pub fn bytes_into_fr(bytes: &[u8]) -> Result<Fr> {
    use anyhow::{ensure, Context};
    ensure!(bytes.len() == 32, Error::BadFrBytes);
    let mut fr_repr = FrRepr::default();
    fr_repr.read_le(bytes).context(Error::BadFrBytes)?;
    Fr::from_repr(fr_repr).map_err(|_| Error::BadFrBytes.into())
}

#[cfg(feature = "blst")]
pub fn bytes_into_fr(bytes: &[u8]) -> Result<Fr> {
    use std::convert::TryInto;
    Fr::from_bytes_le(bytes.try_into().map_err(|_| Error::BadFrBytes)?)
        .ok_or_else(|| Error::BadFrBytes.into())
}

/// Bytes is little-endian.
#[inline]
pub fn bytes_into_fr_repr_safe(r: &[u8]) -> FrRepr {
    debug_assert!(r.len() == 32);

    let repr: [u64; 4] = [
        LittleEndian::read_u64(&r[0..8]),
        LittleEndian::read_u64(&r[8..16]),
        LittleEndian::read_u64(&r[16..24]),
        u64::from(r[31] & 0b0011_1111) << 56
            | u64::from(r[30]) << 48
            | u64::from(r[29]) << 40
            | u64::from(r[28]) << 32
            | u64::from(r[27]) << 24
            | u64::from(r[26]) << 16
            | u64::from(r[25]) << 8
            | u64::from(r[24]),
    ];

    FrRepr(repr)
}

/// Takes an Fr and returns a vector of exactly 32 bytes guaranteed to contain a valid Fr.
#[cfg(feature = "pairing")]
pub fn fr_into_bytes(fr: &Fr) -> Fr32Vec {
    let mut out = Vec::with_capacity(32);
    fr.into_repr().write_le(&mut out).expect("write_le failure");
    out
}

#[cfg(feature = "blst")]
pub fn fr_into_bytes(fr: &Fr) -> Fr32Vec {
    fr.to_bytes_le().to_vec()
}

pub fn u64_into_fr(n: u64) -> Fr {
    Fr::from_repr(FrRepr::from(n)).expect("failed to convert u64 into Fr (should never fail)")
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
