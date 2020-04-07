use aes::Aes256;
use anyhow::{ensure, Context};
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, Cbc};

use crate::error::Result;

const IV: [u8; 16] = [0u8; 16];

pub fn encode(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ensure!(key.len() == 32, "invalid key length");

    let mode = Cbc::<Aes256, ZeroPadding>::new_var(key, &IV).context("invalid key")?;

    Ok(mode.encrypt_vec(plaintext))
}

pub fn decode(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ensure!(key.len() == 32, "invalid key length");

    let mode = Cbc::<Aes256, ZeroPadding>::new_var(key, &IV).context("invalid key")?;

    let res = mode.decrypt_vec(ciphertext).context("failed to decrypt")?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[test]
    fn test_aes() {
        let mut rng = XorShiftRng::from_seed(crate::TEST_SEED);

        for i in 0..10 {
            let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            let plaintext: Vec<u8> = (0..(i + 1) * 32).map(|_| rng.gen()).collect();

            let ciphertext = encode(key.as_slice(), plaintext.as_slice()).unwrap();

            assert_ne!(
                plaintext, ciphertext,
                "plaintext and ciphertext are identical"
            );
            assert_eq!(plaintext.len(), ciphertext.len());

            let roundtrip = decode(key.as_slice(), ciphertext.as_slice()).unwrap();
            assert_eq!(plaintext, roundtrip, "failed to roundtrip");
        }
    }
}
