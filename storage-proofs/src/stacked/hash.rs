use crate::crypto::pedersen::{pedersen, pedersen_md_no_padding};
use crate::hasher::pedersen::PedersenDomain;

/// Hash 2 individual elements.
pub fn hash2(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> PedersenDomain {
    let mut buffer = Vec::with_capacity(a.as_ref().len() + b.as_ref().len());
    buffer.extend_from_slice(a.as_ref());
    buffer.extend_from_slice(b.as_ref());

    hash1(buffer)
}

/// Hash all elements in the given column.
pub fn hash_single_column(column: &[impl AsRef<[u8]>]) -> PedersenDomain {
    let buffer: Vec<u8> = column
        .iter()
        .flat_map(|row| row.as_ref())
        .copied()
        .collect();

    hash1(buffer)
}

/// Hash all elements in the given buffer
pub fn hash1(data: impl AsRef<[u8]>) -> PedersenDomain {
    let data = data.as_ref();

    if data.len() > 32 {
        pedersen_md_no_padding(&data).into()
    } else {
        pedersen(data).into()
    }
}
