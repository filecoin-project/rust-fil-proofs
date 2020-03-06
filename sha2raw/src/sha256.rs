use block_buffer::byteorder::{ByteOrder, BE};

use crate::consts::H256;
use crate::platform::Implementation;

lazy_static::lazy_static! {
    static ref IMPL: Implementation = Implementation::detect();
}

#[derive(Clone)]
pub struct Sha256 {
    len: u64,
    state: [u32; 8],
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256 {
            len: 0,
            state: H256,
        }
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256::default()
    }

    pub fn digest(blocks: &[&[u8]]) -> [u8; 32] {
        let mut sha = Sha256::new();
        sha.input(blocks);
        sha.finish()
    }

    pub fn input(&mut self, blocks: &[&[u8]]) {
        debug_assert_eq!(blocks.len() % 2, 0, "invalid block length");

        self.len += (blocks.len() as u64) << 8;

        IMPL.compress256(&mut self.state, blocks);
    }

    pub fn finish(mut self) -> [u8; 32] {
        let mut block0 = [0u8; 32];
        let mut block1 = [0u8; 32];

        // Append single 1 bit
        block0[0] = 0b1000_0000;

        // Write L as 64 big endian integer
        let l = self.len;
        block1[32 - 8..].copy_from_slice(&l.to_be_bytes()[..]);

        IMPL.compress256(&mut self.state, &[&block0[..], &block1[..]][..]);

        let mut out = [0u8; 32];
        BE::write_u32_into(&self.state, &mut out);
        out
    }

    pub fn finish_with(mut self, block0: &[u8]) -> [u8; 32] {
        debug_assert_eq!(block0.len(), 32);

        let mut block1 = [0u8; 32];

        // Append single 1 bit
        block1[0] = 0b1000_0000;

        // Write L as 64 big endian integer
        let l = self.len + 256;
        block1[32 - 8..].copy_from_slice(&l.to_be_bytes()[..]);

        IMPL.compress256(&mut self.state, &[block0, &block1[..]][..]);

        let mut out = [0u8; 32];
        BE::write_u32_into(&self.state, &mut out);
        out
    }
}

opaque_debug::impl_opaque_debug!(Sha256);

#[cfg(test)]
mod tests {
    use super::*;

    use sha2::{Digest, Sha256 as Original};

    #[test]
    fn test_matching_finish() {
        for k in 1..10 {
            for i in 0..255u8 {
                let input = vec![i; 64 * k];
                let chunked = input.chunks(32).collect::<Vec<_>>();
                assert_eq!(&Sha256::digest(&chunked)[..], &Original::digest(&input)[..])
            }
        }
    }

    #[test]
    fn test_matching_finish_with() {
        for k in 1..10 {
            for i in 0..255u8 {
                let input = vec![i; 32 * k];
                let mut hasher = Sha256::new();
                for chunk in input.chunks(64) {
                    if chunk.len() == 64 {
                        hasher.input(&[&chunk[..32], &chunk[32..]]);
                    }
                }
                let hash = if input.len() % 64 != 0 {
                    hasher.finish_with(&input[input.len() - 32..])
                } else {
                    hasher.finish()
                };
                assert_eq!(&hash[..], &Original::digest(&input)[..])
            }
        }
    }
}
