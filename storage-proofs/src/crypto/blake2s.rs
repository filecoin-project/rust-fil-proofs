use blake2::{Blake2s, Digest};

pub fn blake2s(data: &[u8]) -> Vec<u8> {
    Blake2s::digest(data).to_vec()
}
