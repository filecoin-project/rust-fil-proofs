use byteorder::{ByteOrder, BE};

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

opaque_debug::implement!(Sha256);

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use sha2::{Digest, Sha256 as Original};

    #[test]
    fn test_fuzz_simple() {
        fuzz(10);
    }

    #[test]
    #[ignore]
    fn test_fuzz_long() {
        fuzz(1_000);
    }

    fn fuzz(n: usize) {
        let rng = &mut XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        for k in 1..n {
            for _ in 0..100 {
                let mut input = vec![0u8; 64 * k];
                rng.fill_bytes(&mut input);
                let chunked = input.chunks(32).collect::<Vec<_>>();
                assert_eq!(&Sha256::digest(&chunked)[..], &Original::digest(&input)[..])
            }
        }

        for k in (1..n).step_by(2) {
            for _ in 0..100 {
                let mut input = vec![0u8; 32 * k];
                rng.fill_bytes(&mut input);
                let mut hasher = Sha256::new();
                for chunk in input.chunks(64) {
                    if chunk.len() == 64 {
                        hasher.input(&[&chunk[..32], &chunk[32..]]);
                    }
                }
                assert_eq!(input.len() % 64, 32);
                let hash = hasher.finish_with(&input[input.len() - 32..]);

                assert_eq!(
                    &hash[..],
                    &Original::digest(&input)[..],
                    "input: {:?}",
                    &input
                );
            }
        }
    }
}
