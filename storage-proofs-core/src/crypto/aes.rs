use aes::cipher::block_padding::ZeroPadding;
use aes::cipher::crypto_common::KeyIvInit;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut};
use anyhow::{ensure, Context};

use crate::error::Result;

const IV: [u8; 16] = [0u8; 16];

pub fn encode(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    ensure!(key.len() == 32, "invalid key length");

    let mode = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, &IV).context("invalid key")?;

    Ok(mode.encrypt_padded_vec_mut::<ZeroPadding>(plaintext))
}

pub fn decode(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    ensure!(key.len() == 32, "invalid key length");

    let mode = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &IV).context("invalid key")?;

    let res = mode
        .decrypt_padded_vec_mut::<ZeroPadding>(ciphertext)
        .context("failed to decrypt")?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    use crate::TEST_SEED;

    #[test]
    fn test_aes() {
        let mut rng = XorShiftRng::from_seed(TEST_SEED);

        for i in 0..10 {
            let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            let plaintext: Vec<u8> = (0..(i + 1) * 32).map(|_| rng.gen()).collect();

            let ciphertext =
                encode(key.as_slice(), plaintext.as_slice()).expect("failed to encode");

            assert_ne!(
                plaintext, ciphertext,
                "plaintext and ciphertext are identical"
            );
            assert_eq!(plaintext.len(), ciphertext.len());

            let roundtrip =
                decode(key.as_slice(), ciphertext.as_slice()).expect("failed to decode");
            assert_eq!(plaintext, roundtrip, "failed to roundtrip");
        }
    }
}
