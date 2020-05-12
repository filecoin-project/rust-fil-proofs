//! Implementation of batched hashing using Sha256.

use byteorder::{ByteOrder, LittleEndian};
use ff::PrimeField;
use itertools::Itertools;
use paired::bls12_381::{Fr, FrRepr};
use sha2raw::Sha256;
use storage_proofs_core::{hasher::Domain, util::NODE_SIZE};

use super::Parent;

/// Hashes the provided, non expanded, parents.
///
/// The provided data must be such that the parents expanded by `k` can not overreach
/// and alread bit padded, such that each 32 byte chunk is a valid Fr.
pub fn batch_hash(
    k: usize,
    degree: usize,
    mut hasher: Sha256,
    parents: &[Parent],
    data: &[u8],
) -> [u8; 32] {
    assert!(parents.len() % 2 == 0, "number of parents must be even");
    assert_eq!(parents.len(), degree * k, "invalid number of parents");
    let modulus = Fr::char();

    for (i, j) in (0..degree).tuples() {
        let k = k as u32;

        let (el1, el2) = (0..k).fold(
            (FrRepr::from(0), FrRepr::from(0)),
            |(mut el1, mut el2), l| {
                let y1 = i + (l as usize * degree as usize);
                let parent1 = parents[y1 as usize];
                let current1 = read_at(data, parent1 as usize);
                let y2 = j + (l as usize * degree as usize);
                let parent2 = parents[y2 as usize];
                let current2 = read_at(data, parent2 as usize);

                add_assign(&mut el1, &current1, &modulus);
                add_assign(&mut el2, &current2, &modulus);

                (el1, el2)
            },
        );

        // hash two 32 byte chunks at once
        hasher.input(&[fr_repr_as_slice(&el1), fr_repr_as_slice(&el2)]);
    }

    let mut hash = hasher.finish();
    truncate_hash(&mut hash);

    hash
}

/// Adds two `FrRepr`.
/// This avoids converting to Montgomery form, which is only needed to do multiplications, and
/// happens when converting into and from an `Fr`.
#[inline]
#[cfg(not(target_arch = "x86_64"))]
fn add_assign(a: &mut FrRepr, b: &FrRepr, modulus: &FrRepr) {
    debug_assert_eq!(a.0.len(), 4);

    a.add_nocarry(b);

    // check if we need to reduce by the modulus
    // TODO: Port this check back to fff
    let is_valid = (a.0[3] < modulus.0[3])
        || (a.0[3] == modulus.0[3]
            && ((a.0[2] < modulus.0[2])
                || (a.0[2] == modulus.0[2]
                    && ((a.0[1] < modulus.0[1])
                        || (a.0[1] == modulus.0[1] && (a.0[0] < modulus.0[0]))))));

    if !is_valid {
        a.sub_noborrow(&Fr::char());
    }
}

#[inline]
#[cfg(target_arch = "x86_64")]
fn add_assign(a: &mut FrRepr, b: &FrRepr, modulus: &FrRepr) {
    use std::arch::x86_64::*;
    use std::mem;

    unsafe {
        let mut carry = _addcarry_u64(0, a.0[0], b.0[0], &mut a.0[0]);
        carry = _addcarry_u64(carry, a.0[1], b.0[1], &mut a.0[1]);
        carry = _addcarry_u64(carry, a.0[2], b.0[2], &mut a.0[2]);
        _addcarry_u64(carry, a.0[3], b.0[3], &mut a.0[3]);

        let mut s_sub = [0u64; 4];

        carry = _subborrow_u64(0, a.0[0], modulus.0[0], &mut s_sub[0]);
        carry = _subborrow_u64(carry, a.0[1], modulus.0[1], &mut s_sub[1]);
        carry = _subborrow_u64(carry, a.0[2], modulus.0[2], &mut s_sub[2]);
        carry = _subborrow_u64(carry, a.0[3], modulus.0[3], &mut s_sub[3]);

        if carry == 0 {
            a.0 = s_sub;
        }
    }
}

// TODO: move back to core
// TODO: panic if not on the right endianess
// TODO: figure out if we can use write_le instead
#[inline(always)]
#[allow(clippy::needless_lifetimes)]
fn fr_repr_as_slice<'a>(a: &'a FrRepr) -> &'a [u8] {
    unsafe {
        std::slice::from_raw_parts(
            a.0.as_ptr() as *const u8,
            a.0.len() * std::mem::size_of::<u64>(),
        )
    }
}

/// Hashes the provided, expanded, parents.
pub fn batch_hash_expanded<D: Domain>(
    k: usize,
    degree: usize,
    mut hasher: Sha256,
    parents_data: &[D],
) -> [u8; 32] {
    assert!(
        parents_data.len() % 2 == 0,
        "number of parents must be even"
    );
    assert_eq!(parents_data.len(), degree * k, "invalid number of parents");
    let modulus = Fr::char();

    for (i, j) in (0..degree).tuples() {
        let mut el1 = FrRepr::from(0);
        let mut el2 = FrRepr::from(0);
        let k = k as u32;

        for l in 0..k {
            let y1 = i + (l as usize * degree as usize);
            let current1 = parents_data[y1].into_repr();
            add_assign(&mut el1, &current1, &modulus);

            let y2 = j + (l as usize * degree as usize);
            let current2 = parents_data[y2].into_repr();
            add_assign(&mut el2, &current2, &modulus);
        }

        // hash two 32 byte chunks at once
        hasher.input(&[fr_repr_as_slice(&el1), fr_repr_as_slice(&el2)]);
    }

    let mut hash = hasher.finish();
    truncate_hash(&mut hash);

    hash
}

/// Read an `FrRepr` at the given index.
#[inline]
fn read_at(data: &[u8], index: usize) -> FrRepr {
    let slice = &data[index * NODE_SIZE..(index + 1) * NODE_SIZE];
    fr_repr_from_slice(slice)
}

/// Reads the first 32 bytes from the given slice and
/// processes them as `FrRepr`. Does not validate that
/// they are valid FrReprs.
#[inline]
fn fr_repr_from_slice(r: &[u8]) -> FrRepr {
    let repr = [
        LittleEndian::read_u64(&r[..8]),
        LittleEndian::read_u64(&r[8..16]),
        LittleEndian::read_u64(&r[16..24]),
        LittleEndian::read_u64(&r[24..]),
    ];
    FrRepr(repr)
}

pub fn truncate_hash(hash: &mut [u8]) {
    assert_eq!(hash.len(), 32);
    // strip last two bits, to ensure result is in Fr.
    hash[31] &= 0b0011_1111;
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::Field;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::fr32::{bytes_into_fr, fr_into_bytes};

    #[test]
    fn test_read_at() {
        let data = [0u8; 64];

        let v0 = read_at(&data, 0);
        assert_eq!(v0, FrRepr::from(0));
        let v1 = read_at(&data, 1);
        assert_eq!(v1, FrRepr::from(0));
    }

    #[test]
    fn test_truncate_hash() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..1000 {
            // random bytes
            let mut input: [u8; 32] = rng.gen();
            truncate_hash(&mut input);

            // check for valid Fr
            bytes_into_fr(&input).expect("invalid fr created");
        }
    }

    #[test]
    fn test_add_assign() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);
        let modulus = Fr::char();
        for _ in 0..1000 {
            let mut a = Fr::random(rng);
            let b = Fr::random(rng);

            let mut a_repr = a.clone().into_repr();
            let b_repr = b.clone().into_repr();

            add_assign(&mut a_repr, &b_repr, &modulus);
            a.add_assign(&b);

            let a_back = Fr::from_repr(a_repr).unwrap();
            assert_eq!(a, a_back);
        }
    }

    #[test]
    fn test_fr_repr_from_slice() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        for _ in 0..1000 {
            let a = Fr::random(rng);
            let a_repr = a.clone().into_repr();
            let slice = fr_into_bytes(&a);

            let a_repr_back = fr_repr_from_slice(&slice);
            assert_eq!(a_repr, a_repr_back);
        }
    }
}
