use crate::crypto::pedersen::{pedersen_bits, pedersen_md_no_padding_bits, Bits};
use crate::hasher::pedersen::PedersenDomain;

/// Hash 2 individual elements.
pub fn hash2<S: AsRef<[u8]>, T: AsRef<[u8]>>(a: S, b: T) -> PedersenDomain {
    hash1(Bits::new_vec(vec![a.as_ref(), b.as_ref()]))
}

/// Hash all elements in the given column.
pub fn hash_single_column<T: AsRef<[u8]>>(column: &[T]) -> PedersenDomain {
    hash1(Bits::new_vec(column.iter().map(|t| t.as_ref()).collect()))
}

/// Hash all elements in the given buffer
pub fn hash1(data: Bits) -> PedersenDomain {
    if data.len() > 32 {
        pedersen_md_no_padding_bits(data).into()
    } else {
        pedersen_bits(data).into()
    }
}
