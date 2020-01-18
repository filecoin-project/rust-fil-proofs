use sha2::Digest;

use crate::crypto::pedersen::{pedersen_md_no_padding_bits, Bits};
use crate::hasher::{pedersen::PedersenDomain, Domain};

/// Hash 2 individual elements.
pub fn hash2<S: AsRef<[u8]>, T: AsRef<[u8]>>(a: S, b: T) -> PedersenDomain {
    hash1(Bits::new_many(vec![a.as_ref(), b.as_ref()].into_iter()))
}

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

/// Hash all elements in the given buffer
pub fn hash1<'a, S: Iterator<Item = &'a [u8]>>(data: Bits<&'a [u8], S>) -> PedersenDomain {
    pedersen_md_no_padding_bits(data).into()
}
