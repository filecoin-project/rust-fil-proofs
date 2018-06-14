use error::Result;
use openssl::symm::{Cipher, Crypter, Mode};

pub fn encode(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        panic!("invalid key length");
    }

    let iv = vec![0u8; 16];

    // Create a cipher context for encryption.
    let mut encrypter = Crypter::new(
        Cipher::aes_256_cbc(),
        Mode::Encrypt,
        key,
        Some(iv.as_slice()),
    )?;
    encrypter.pad(false);

    let block_size = Cipher::aes_256_cbc().block_size();
    let mut ciphertext = vec![0; plaintext.len() + block_size];

    let mut count = encrypter.update(plaintext, &mut ciphertext)?;
    count += encrypter.finalize(&mut ciphertext[count..])?;
    ciphertext.truncate(count);

    Ok(ciphertext)
}

pub fn decode(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        panic!("invalid key length")
    }

    let iv = vec![0u8; 16];
    // Create a cipher context for decryption.
    let mut decrypter = Crypter::new(
        Cipher::aes_256_cbc(),
        Mode::Decrypt,
        key,
        Some(iv.as_slice()),
    )?;
    decrypter.pad(false);

    let block_size = Cipher::aes_256_cbc().block_size();
    let mut plaintext = vec![0; ciphertext.len() + block_size];

    // Decrypt 2 chunks of ciphertexts successively.
    let mut count = decrypter.update(ciphertext, &mut plaintext)?;
    count += decrypter.finalize(&mut plaintext[count..])?;
    plaintext.truncate(count);

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
