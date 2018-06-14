use bigdecimal::BigDecimal;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::cast::FromPrimitive;
use std::iter::FlatMap;
use std::ops::DivAssign;
use std::ops::Rem;
use std::str::FromStr;

static P_BYTES: &[u8] =
    b"52435875175126190479447740508185965837690552500527637822603658699938581184513";

lazy_static! {
    static ref P: BigUint = BigUint::parse_bytes(P_BYTES, 10).unwrap();

    // Might need this later.
    static ref DECIMAL_P: BigDecimal = BigDecimal::from_str(
        "52435875175126190479447740508185965837690552500527637822603658699938581184513"
    ).unwrap();
    // It's surprisingly hard to calculate this in Rust, so just import the result for now.
    static ref P_LOG2: f64 = 254.857089413;
}

#[derive(Debug)]
struct BigUintDigits {
    base: BigUint,
    n: BigUint,
    digit_count: usize,
}

impl Iterator for BigUintDigits {
    type Item = BigUint;

    fn next(&mut self) -> Option<Self::Item> {
        let rem = (&self.n).rem(&self.base);
        self.n.div_assign(&self.base);

        if self.digit_count == 0 {
            None
        } else {
            self.digit_count -= 1;
            Some(rem)
        }
    }
}

#[derive(Debug)]
struct Chunks<'a> {
    input: &'a [u8],
    size: usize,
}

impl<'a> Iterator for Chunks<'a> {
    type Item = BigUint;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            None
        } else {
            let chunk = BigUint::from_bytes_le(&self.input[0..self.size]);
            self.input = &self.input[self.size..self.input.len()];
            Some(chunk)
        }
    }
}

fn chunks(size: usize, input: &[u8]) -> Chunks {
    Chunks { input, size }
}

fn big_uint_digits(base: BigUint, digit_count: usize, n: BigUint) -> BigUintDigits {
    BigUintDigits {
        base,
        n,
        digit_count,
    }
}

fn big_uint_from_digits(base: BigUint, digits: &[BigUint]) -> BigUint {
    digits.iter().rev().fold(big(0), |mut acc, digit| {
        acc *= &base;
        acc += digit;
        acc
    })
}

fn pack(base: BigUint, digit_count: usize, bytes: &[u8]) -> BigUintDigits {
    let big = BigUint::from_bytes_le(bytes);
    big_uint_digits(base, digit_count, big)
}

// Byte could be calculated.
fn unpack(base: BigUint, byte_count: usize, digits: &[BigUint]) -> Vec<u8> {
    let big = big_uint_from_digits(base, digits);
    let bytes = BigUint::to_bytes_le(&big);

    let mut padded = vec![0; byte_count];
    for (i, b) in bytes.iter().enumerate() {
        padded[i] = *b;
    }
    padded
}

fn big(x: u64) -> BigUint {
    BigUint::from_u64(x).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digits() {
        let base = big(5);
        let num = big(27);
        let digit_count = 4;
        let elts: Vec<BigUint> = big_uint_digits(base.clone(), digit_count, num.clone()).collect();

        assert_eq!(vec![big(2), big(0), big(1), big(0)], elts);

        let back_again = big_uint_from_digits(base, &elts);

        assert_eq!(num, back_again);
    }

    #[test]
    fn test_chunks() {
        let chunks: Vec<BigUint> = chunks(2, b"This is stuff.").collect();
        let expect: Vec<BigUint> = vec![];
        println!("chunks {:?}", chunks);
        assert_eq!(expect, chunks);
    }

    fn pack_test(plaintext: &[u8], p: BigUint, digit_count: usize, expect_success: bool) {
        let byte_count = plaintext.len();
        let packed: Vec<BigUint> = pack(p.clone(), digit_count, plaintext).collect();

        // A 'digit' will be a field element.
        assert_eq!(digit_count, packed.len());

        let unpacked = unpack(p, byte_count, &packed);
        if expect_success {
            assert_eq!(plaintext.to_vec(), unpacked);
        } else {
            assert_ne!(plaintext.to_vec(), unpacked);
        }
    }

    #[test]
    fn test_pack() {
        let msg = b"This is just some text.";

        assert_eq!(23, msg.len());

        // 23-byte message packs into 65 base-7 digits.
        pack_test(msg, big(7), 65, true);
        pack_test(msg, big(7), 64, false); // 64 is not enough.

        // This is an important test of padding. A message of all 0 will otherwise be truncated when unpacked.
        pack_test(&[0; 23], big(7), 65, true);

        // 23-byte message packs into 38 base-29 digits.
        pack_test(msg, big(29), 38, true);
        pack_test(msg, big(29), 37, false);

        // 23-byte message packs into 20 base-693 digits.
        pack_test(msg, big(693), 20, true);
        pack_test(msg, big(693), 19, false); // 19 is not enough.

        // 23-byte message packs into 5 base-123456789123 digits.
        pack_test(msg, big(123456789123), 5, true);
        pack_test(msg, big(123456789123), 4, false); // 4 is not enough.

        // p is from bls12_381::Fr
        let p = BigUint::parse_bytes(P_BYTES, 10).unwrap();

        // 23-byte message packs into 1 base-p digit.
        pack_test(msg, p.clone(), 1, true);

        // 961-byte message packs into 31 base-p digits.
        pack_test(&[1; 961], p.clone(), 31, true);
        pack_test(&[1; 961], p.clone(), 30, false);
        // 961 bytes is exactly 31 x 31-byte chunks.
        // After expanding 31 bytes to 32 bytes, this is 992 bytes.
        // One base-p element still requires 32 bytes,
        // So packing into base-p saves 992 - (31 x 32 = 992) = 0 bytes.

        // 987-byte message packs into 31 base-p digits.
        pack_test(&[1; 987], p.clone(), 31, true);
        pack_test(&[1; 987], p.clone(), 30, false); // 30 is not enough.

        // But in the unaligned case, 987 bytes requires 32 31-byte chunks to fit completely, for a total of 32 x 32 encrypted = 1024  bytes.
        // Packing into base-p still takes 31 * 32 = 992 bytes, for a savings of 1024 - 992 = 32 bytes.

        // TODO: formalize this computation to allow selection of an optimal chunk-size,
        // balancing memory consumption and cost of packing against space savings.
    }
}
