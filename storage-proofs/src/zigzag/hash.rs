use blake2s_simd::Params as Blake2s;

use crate::util::NODE_SIZE;

/// Hash 2 individual elements.
pub fn hash2(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> Vec<u8> {
    let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
    hasher.update(a.as_ref());
    hasher.update(b.as_ref());

    hasher.finalize().as_ref().to_vec()
}

/// Hash all elements in the given column. Useful when the column already only contains even or odd values.
pub fn hash_single_column(column: &[impl AsRef<[u8]>]) -> Vec<u8> {
    let mut hasher = Blake2s::new().hash_length(NODE_SIZE).to_state();
    for row in column.iter() {
        hasher.update(row.as_ref());
    }
    hasher.finalize().as_ref().to_vec()
}
