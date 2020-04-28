//! Implementation of batched hashing using Sha256.

use ff::Field;
use paired::bls12_381::Fr;
use sha2raw::Sha256;
use storage_proofs_core::fr32::bytes_into_fr;
use storage_proofs_core::hasher::Sha256Domain;
use storage_proofs_core::util::NODE_SIZE;

use super::Parent;

/// Hashes the provided, non expanded, parents.
///
/// The provided data must be such that the parents expanded by `k` can not overreach
/// and alread bit padded, such that each 32 byte chunk is a valid Fr.
pub fn batch_hash(k: usize, degree: usize, parents: &[Parent], data: &[u8]) -> Sha256Domain {
    assert!(parents.len() % 2 == 0, "number of parents must be even");
    assert_eq!(parents.len(), degree * k, "invalid number of parents");

    let mut hasher = Sha256::new();

    let mut tmp = Sha256Domain::default();

    for i in 0..degree {
        let mut el = Fr::zero();

        for l in 0..k {
            let parent = parents[i + l * degree];
            let current = read_at(data, parent as usize);
            el.add_assign(&current);
        }

        // hash two 32 byte chunks at once
        if i % 2 == 0 {
            tmp = el.into();
        } else {
            let el: Sha256Domain = el.into();
            hasher.input(&[AsRef::<[u8]>::as_ref(&tmp), AsRef::<[u8]>::as_ref(&el)]);
        }
    }

    let mut hash = Sha256Domain(hasher.finish());
    hash.trim_to_fr32();

    hash
}

/// Read an `Fr` at the given index.
fn read_at(data: &[u8], index: usize) -> Fr {
    let slice = &data[index * NODE_SIZE..(index + 1) * NODE_SIZE];
    bytes_into_fr(slice).expect("invalid data")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_at() {
        let data = [0u8; 64];

        let v0 = read_at(&data, 0);
        assert_eq!(v0, Fr::zero());
        let v1 = read_at(&data, 1);
        assert_eq!(v1, Fr::zero());
    }
}
