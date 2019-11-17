use crate::crypto::pedersen::{pedersen_md_no_padding_bits, Bits};
use crate::hasher::pedersen::PedersenDomain;

/// Hash 2 individual elements.
pub fn hash2<S: AsRef<[u8]>, T: AsRef<[u8]>>(a: S, b: T) -> PedersenDomain {
    hash1(Bits::new_many(vec![a.as_ref(), b.as_ref()].into_iter()))
}

/// Hash 3 individual elements.
pub fn hash3<S: AsRef<[u8]>, T: AsRef<[u8]>, U: AsRef<[u8]>>(a: S, b: T, c: U) -> PedersenDomain {
    hash1(Bits::new_many(
        vec![a.as_ref(), b.as_ref(), c.as_ref()].into_iter(),
    ))
}

/// Hash all elements in the given column.
pub fn hash_single_column<T: AsRef<[u8]>>(column: &[T]) -> PedersenDomain {
    hash1(Bits::new_many(column.iter().map(|t| t.as_ref())))
}

/// Hash all elements in the given buffer
pub fn hash1<'a, S: Iterator<Item = &'a [u8]>>(data: Bits<&'a [u8], S>) -> PedersenDomain {
    pedersen_md_no_padding_bits(data).into()
}
