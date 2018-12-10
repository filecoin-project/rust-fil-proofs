use crate::error::Result;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::Aes256;
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, BlockModeIv, Cbc};

pub fn encode(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(key.len(), 32, "invalid key length");

    let iv = GenericArray::from_slice(&[0u8; 16]);
    let mut mode = Cbc::<Aes256, ZeroPadding>::new_varkey(key, iv).expect("invalid key");

    let mut ciphertext = plaintext.to_vec();
    mode.encrypt_nopad(&mut ciphertext)
        .expect("failed to encrypt");

    Ok(ciphertext)
}

pub fn decode(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(key.len(), 32, "invalid key length");
    let iv = GenericArray::from_slice(&[0u8; 16]);

    let mut mode = Cbc::<Aes256, ZeroPadding>::new_varkey(key, iv).expect("invalid key");

    let mut plaintext = ciphertext.to_vec();
    mode.decrypt_nopad(&mut plaintext)
        .expect("failed to decrypt");

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_aes() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

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
