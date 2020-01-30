use sha2::Digest;

use crate::hasher::{pedersen::PedersenDomain, Domain};

/// Hash all elements in the given column.
pub fn hash_single_column<T: AsRef<[u8]>>(column: &[T]) -> PedersenDomain {
    let mut hasher = sha2::Sha256::new();
    for t in column {
        hasher.input(t.as_ref());
    }
    let mut res = hasher.result();
    res[31] &= 0b0011_1111;
    PedersenDomain::try_from_bytes(&res).unwrap()
}
