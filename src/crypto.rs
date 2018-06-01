use rcrypto::aes::{self, KeySize};
use rcrypto::symmetriccipher::SynchronousStreamCipher;

use ring::digest::{Context, SHA256};

pub fn kdf(data: &[u8]) -> Vec<u8> {
    let mut context = Context::new(&SHA256);
    context.update(data);
    context.clone().finish().as_ref().into()
}

pub fn encode(key: &[u8], plaintext: &[u8], output: &mut [u8]) {
    if key.len() != 32 {
        panic!("invalid key length");
    }

    let iv = vec![0u8; 32];
    let mut cipher = aes::ctr(KeySize::KeySize256, key, iv.as_slice());

    cipher.process(plaintext, output);
}
