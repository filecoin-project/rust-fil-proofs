use error::Result;
use openssl::symm::{Cipher, Crypter, Mode};

pub mod feistel;
pub mod kdf;
pub mod pedersen;

// TODO: move below

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

#[test]
fn test_encode_decode() {
    let key = vec![2u8; 32];
    let plaintext = vec![1u8; 128];

    let ciphertext = encode(key.as_slice(), plaintext.as_slice()).unwrap();
    assert_ne!(plaintext, ciphertext);
    assert_eq!(plaintext.len(), ciphertext.len());

    let roundtrip = decode(key.as_slice(), ciphertext.as_slice()).unwrap();
    assert_eq!(plaintext, roundtrip);
}
