use crate::error::Result;

/// Encodes plaintext by elementwise xoring with the passed in key.
pub fn encode(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    xor(key, plaintext)
}

/// Decodes ciphertext by elementwise xoring with the passed in key.
pub fn decode(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    xor(key, ciphertext)
}

fn xor(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let key_len = key.len();
    assert_eq!(key_len, 32);

    Ok(input
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key_len])
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_xor() {
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
