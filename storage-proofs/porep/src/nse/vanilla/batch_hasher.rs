//! Implementation of batched hashing using Sha256.

use ff::Field;
use itertools::Itertools;
use paired::bls12_381::Fr;
use sha2raw::Sha256;
use storage_proofs_core::fr32::bytes_into_fr;
use storage_proofs_core::hasher::{Domain, Sha256Domain};
use storage_proofs_core::util::NODE_SIZE;

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
    assert_eq!(parents.len(), degree, "invalid number of parents");

    for (i, j) in (0..degree).tuples() {
        let mut el1 = Fr::zero();
        let mut el2 = Fr::zero();
        let k = k as u32;

        for l in 0..k {
            // First calculates the index required for the batch hashing
            let y1 = i + (l as usize * degree as usize);
            // then expands the non expanded parent on the fly to retrieve it.
            let parent1 = parents[y1 / k as usize] * k + (y1 as u32) % k;
            let current1 = read_at(data, parent1 as usize);
            el1.add_assign(&current1);

            // First calculates the index required for the batch hashing
            let y2 = j + (l as usize * degree as usize);
            // then expands the non expanded parent on the fly to retrieve it.
            let parent2 = parents[y2 / k as usize] * k + (y2 as u32) % k;
            let current2 = read_at(data, parent2 as usize);
            el2.add_assign(&current2);
        }

        // hash two 32 byte chunks at once
        let el1: Sha256Domain = el1.into();
        let el2: Sha256Domain = el2.into();
        hasher.input(&[AsRef::<[u8]>::as_ref(&el1), AsRef::<[u8]>::as_ref(&el2)]);
    }

    let mut hash = hasher.finish();
    truncate_hash(&mut hash);

    hash
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

    for (i, j) in (0..degree).tuples() {
        let mut el1 = Fr::zero();
        let mut el2 = Fr::zero();
        let k = k as u32;

        for l in 0..k {
            let y1 = i + (l as usize * degree as usize);
            let current1 = parents_data[y1].into();
            el1.add_assign(&current1);

            let y2 = j + (l as usize * degree as usize);
            let current2 = parents_data[y2].into();
            el2.add_assign(&current2);
        }

        // hash two 32 byte chunks at once
        let el1: Sha256Domain = el1.into();
        let el2: Sha256Domain = el2.into();
        hasher.input(&[AsRef::<[u8]>::as_ref(&el1), AsRef::<[u8]>::as_ref(&el2)]);
    }

    let mut hash = hasher.finish();
    truncate_hash(&mut hash);

    hash
}

/// Read an `Fr` at the given index.
fn read_at(data: &[u8], index: usize) -> Fr {
    let slice = &data[index * NODE_SIZE..(index + 1) * NODE_SIZE];
    bytes_into_fr(slice).expect("invalid data")
}

pub fn truncate_hash(hash: &mut [u8]) {
    assert_eq!(hash.len(), 32);
    // strip last two bits, to ensure result is in Fr.
    hash[31] &= 0b0011_1111;
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_read_at() {
        let data = [0u8; 64];

        let v0 = read_at(&data, 0);
        assert_eq!(v0, Fr::zero());
        let v1 = read_at(&data, 1);
        assert_eq!(v1, Fr::zero());
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
}
