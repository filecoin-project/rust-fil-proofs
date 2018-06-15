use error::Result;
use fr32::{bytes_into_frs, fr_into_bytes, Fr32Vec};
use pairing::{Engine, Field};

/// The `v` constant for sloth.
/// This is the same as in `Fr::from_str("20974350070050476191779096203274386335076221000211055129041463479975432473805").unwrap().into_repr()`.
const SLOTH_V: [u64; 4] = [
    3_689_348_813_023_923_405,
    2_413_663_763_415_232_921,
    16_233_882_818_423_549_954,
    3_341_406_743_785_779_740,
];

/// The number five, as an array so we can use it in `pow`.
const FIVE: [u64; 1] = [5];

pub fn encode<'a, E: Engine>(key: &E::Fr, mut plaintext: &[u8], rounds: usize) -> Result<Fr32Vec> {
    let frs = bytes_into_frs::<E>(&mut plaintext)?;
    Ok(frs
        .into_iter()
        .map(|fr| encode_element::<E>(key, &fr, rounds))
        .flat_map(|fr| fr_into_bytes::<E>(&fr))
        .collect())
}

pub fn decode<'a, E: Engine>(key: &E::Fr, mut ciphertext: &[u8], rounds: usize) -> Result<Vec<u8>> {
    let frs = bytes_into_frs::<E>(&mut ciphertext)?;
    Ok(frs
        .into_iter()
        .map(|fr| decode_element::<E>(key, &fr, rounds))
        .flat_map(|fr| fr_into_bytes::<E>(&fr))
        .collect())
}

/// Sloth based encoding.
pub fn encode_element<E: Engine>(key: &E::Fr, plaintext: &E::Fr, rounds: usize) -> E::Fr {
    let mut ciphertext = *plaintext;

    for _ in 0..rounds {
        ciphertext.add_assign(key); // c + k
        ciphertext = ciphertext.pow(&SLOTH_V) // (c + k)^v
    }

    ciphertext
}

/// Sloth based decoding.
pub fn decode_element<E: Engine>(key: &E::Fr, ciphertext: &E::Fr, rounds: usize) -> E::Fr {
    let mut plaintext = *ciphertext;

    for _ in 0..rounds {
        plaintext = plaintext.pow(&FIVE); // c^5
        plaintext.sub_assign(key); // c^5 - k
    }

    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr, FrRepr};
    use pairing::PrimeField;

    // the modulus from `bls12_381::Fr`
    const MODULUS: [u64; 4] = [
        0xffffffff00000001,
        0x53bda402fffe5bfe,
        0x3339d80809a1d805,
        0x73eda753299d7d48,
    ];

    #[test]
    fn sloth_bls_12() {
        let key = Fr::from_str("11111111").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = encode_element::<Bls12>(&key, &plaintext, 10);
        let decrypted = decode_element::<Bls12>(&key, &ciphertext, 10);
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn test_sloth_bls_12_bytes() {
        let key = Fr::from_str("11111111").unwrap();
        let plaintext = b"Exactly thirty-two bytes in all.".to_vec();
        let ciphertext = encode::<Bls12>(&key, &plaintext[..], 10).unwrap();
        let decrypted = decode::<Bls12>(&key, &ciphertext, 10).unwrap();
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn test_sloth_bls_12_bytes_bad() {
        let key = Fr::from_str("11111111").unwrap();
        let plaintext = b"Not quite the right number of bytes.".to_vec();
        let ciphertext = encode::<Bls12>(&key, &plaintext[..], 10);
        assert!(ciphertext.is_err());
    }

    #[test]
    fn sloth_bls_12_fake() {
        let key = Fr::from_str("11111111").unwrap();
        let key_fake = Fr::from_str("11111112").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = encode_element::<Bls12>(&key, &plaintext, 10);
        let decrypted = decode_element::<Bls12>(&key_fake, &ciphertext, 10);
        assert_ne!(plaintext, decrypted);
    }

    #[test]
    fn test_sloth_bls_12_fake_bytes() {
        let key = Fr::from_str("11111111").unwrap();
        let key_fake = Fr::from_str("22222222").unwrap();
        let plaintext = b"Exactly thirty-two bytes in all.".to_vec();
        let ciphertext = encode::<Bls12>(&key, &plaintext, 10).unwrap();
        let decrypted = decode::<Bls12>(&key_fake, &ciphertext, 10).unwrap();
        assert_ne!(plaintext, decrypted);
    }

    prop_compose! {
        fn arb_fr()(a in 0..MODULUS[0], b in 0..MODULUS[1], c in 0..MODULUS[2], d in 0..MODULUS[3]) -> Fr {
            Fr::from_repr(FrRepr([a, b, c, d])).unwrap()
        }
    }
    proptest!{
        #[test]
        fn sloth_bls_roundtrip(key in arb_fr(), plaintext in arb_fr()) {
            let ciphertext = encode_element::<Bls12>(&key, &plaintext, 10);
            assert_eq!(decode_element::<Bls12>(&key, &ciphertext, 10), plaintext);
        }
    }
    prop_compose! {
        fn arb_fr32()(body in 0..0b11111111u8, end in 0..0b00111111u8 // Last byte must have two-bits padding in most-significant bit.
         ) -> Fr32Vec {
            [body, body, body, body, body, body, body, body, body, body, body, body, body, body, body, body,
            body, body, body, body, body, body, body, body, body, body, body, body, body, body, body, end,
           ] .to_vec()
        }
    }

    proptest!{
        #[test]
        fn sloth_bls_bytes_roundtrip(key in arb_fr(), ref plaintext in arb_fr32()) {
            let ciphertext = encode::<Bls12>(&key, &plaintext, 10).unwrap();
            assert_eq!(&decode::<Bls12>(&key, &ciphertext, 10).unwrap(), plaintext);
        }
    }
}
