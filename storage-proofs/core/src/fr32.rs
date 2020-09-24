use crate::error::*;

use anyhow::{ensure, Context};
use bellperson::bls::{Fr, FrRepr};
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use ff::{PrimeField, PrimeFieldRepr};

// Contains 32 bytes whose little-endian value represents an Fr.
// Invariants:
// - Value MUST represent a valid Fr.
// - Length must be 32.
pub type Fr32 = [u8];

// Contains one or more 32-byte chunks whose little-endian values represent Frs.
// Invariants:
// - Value of each 32-byte chunks MUST represent valid Frs.
// - Total length must be a multiple of 32.
// That is to say: each 32-byte chunk taken alone must be a valid Fr32.
pub type Fr32Vec = Vec<u8>;

// Array whose little-endian value represents an Fr.
// Invariants:
// - Value MUST represent a valid Fr.
pub type Fr32Ary = [u8; 32];

// Takes a slice of bytes and returns an Fr if byte slice is exactly 32 bytes and does not overflow.
// Otherwise, returns a BadFrBytesError.
#[cfg(feature = "pairing")]
pub fn bytes_into_fr(bytes: &[u8]) -> Result<Fr> {
    ensure!(bytes.len() == 32, Error::BadFrBytes);

    let mut fr_repr = <<Fr as PrimeField>::Repr as Default>::default();
    fr_repr.read_le(bytes).context(Error::BadFrBytes)?;

    Fr::from_repr(fr_repr).map_err(|_| Error::BadFrBytes.into())
}

#[cfg(feature = "blst")]
pub fn bytes_into_fr(bytes: &[u8]) -> Result<Fr> {
    use std::convert::TryInto;

    Fr::from_bytes_le(bytes.try_into().map_err(|_| Error::BadFrBytes)?)
        .ok_or_else(|| Error::BadFrBytes.into())
}

#[inline]
pub fn trim_bytes_to_fr_safe(r: &[u8]) -> Result<Vec<u8>> {
    ensure!(r.len() == 32, Error::BadFrBytes);
    let mut res = r[..32].to_vec();
    // strip last two bits, to ensure result is in Fr.
    res[31] &= 0b0011_1111;
    Ok(res)
}

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

// Takes an Fr and returns a vector of exactly 32 bytes guaranteed to contain a valid Fr.
#[cfg(feature = "pairing")]
pub fn fr_into_bytes(fr: &Fr) -> Fr32Vec {
    let mut out = Vec::with_capacity(32);
    fr.into_repr().write_le(&mut out).expect("write_le failure");
    out
}

#[cfg(feature = "blst")]
pub fn fr_into_bytes(fr: &Fr) -> Fr32Vec {
    use std::convert::TryInto;

    fr.to_bytes_le().to_vec()
}

// Takes a slice of bytes and returns a vector of Fr -- or an error if either bytes is not a multiple of 32 bytes
// or any 32-byte chunk overflows and does not contain a valid Fr.
pub fn bytes_into_frs(bytes: &[u8]) -> Result<Vec<Fr>> {
    bytes
        .chunks(32)
        .map(|ref chunk| bytes_into_fr(chunk))
        .collect()
}

// Takes a slice of Frs and returns a vector of bytes, guaranteed to have a size which is a multiple of 32,
// with every 32-byte chunk representing a valid Fr.
pub fn frs_into_bytes(frs: &[Fr]) -> Fr32Vec {
    frs.iter().flat_map(|fr| fr_into_bytes(fr)).collect()
}

// Takes a u32 and returns an Fr.
pub fn u32_into_fr(n: u32) -> Fr {
    let mut buf: Fr32Vec = vec![0u8; 32];
    let mut w = &mut buf[0..4];
    w.write_u32::<LittleEndian>(n).expect("write_u32 failure");

    bytes_into_fr(&buf).expect("should never fail since u32 is in the field")
}

// Takes a u64 and returns an Fr.
pub fn u64_into_fr(n: u64) -> Fr {
    let mut buf: Fr32Vec = vec![0u8; 32];
    let mut w = &mut buf[0..8];
    w.write_u64::<LittleEndian>(n).expect("write_u64 failure");

    bytes_into_fr(&buf).expect("should never fail since u64 is in the field")
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

    fn bytes_into_frs_into_bytes_test(bytes: &Fr32) {
        let frs = bytes_into_frs(bytes).expect("Failed to convert bytes into a `Vec<Fr>`");
        assert!(frs.len() == 3);
        let bytes_back = frs_into_bytes(&frs);
        assert!(bytes.to_vec() == bytes_back);
    }

    #[test]
    fn test_bytes_into_frs_into_bytes() {
        let bytes = b"012345678901234567890123456789--012345678901234567890123456789--012345678901234567890123456789--";
        bytes_into_frs_into_bytes_test(&bytes[..]);

        let _short_bytes = b"012345678901234567890123456789--01234567890123456789";
        // This will panic because _short_bytes is not a multiple of 32 bytes.
        // bytes_into_frs_into_bytes_test(&_short_bytes[..]);
    }
}
