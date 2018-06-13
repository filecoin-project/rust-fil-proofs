use blake2_rfc::blake2s::Blake2s;

const KDF_BLAKE2S_HASH_SIZE: usize = 32;

pub fn blake2s(data: &[u8]) -> Vec<u8> {
    let mut context = Blake2s::new(KDF_BLAKE2S_HASH_SIZE);
    context.update(data);
    context.finalize().as_bytes().to_vec()
}
