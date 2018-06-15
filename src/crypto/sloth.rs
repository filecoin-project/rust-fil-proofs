use pairing::{Engine, Field};

// is the same as in `Fr::from_str("20974350070050476191779096203274386335076221000211055129041463479975432473805").unwrap().into_repr()`
const SLOTH_V: [u64; 4] = [
    3689348813023923405,
    2413663763415232921,
    16233882818423549954,
    3341406743785779740,
];

/// Sloth based encoding.
pub fn encode<E: Engine>(key: &E::Fr, plaintext: &E::Fr) -> E::Fr {
    let mut tmp = plaintext.clone();
    tmp.add_assign(key); // c + k
    tmp.pow(&SLOTH_V) // (c + k)^v
}

/// Sloth based decoding
pub fn decode<E: Engine>(key: &E::Fr, ciphertext: &E::Fr) -> E::Fr {
    let mut tmp = ciphertext.pow(&[5]); // c^5
    tmp.sub_assign(key); // c^5 - k

    tmp
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, Fr, FrRepr};
    use pairing::PrimeField;

    const MODULUS: [u64; 4] = [
        0xffffffff00000001,
        0x53bda402fffe5bfe,
        0x3339d80809a1d805,
        0x73eda753299d7d48,
    ];

    #[test]
    fn test_sloth_bls_12() {
        let key = Fr::from_str("11111111").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = encode::<Bls12>(&key, &plaintext);
        let decrypted = decode::<Bls12>(&key, &ciphertext);
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn test_sloth_bls_12_fake() {
        let key = Fr::from_str("11111111").unwrap();
        let key_fake = Fr::from_str("11111112").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = encode::<Bls12>(&key, &plaintext);
        let decrypted = decode::<Bls12>(&key_fake, &ciphertext);
        assert_ne!(plaintext, decrypted);
    }

    prop_compose! {
        fn arb_fr()(a in 0..MODULUS[0], b in 0..MODULUS[1], c in 0..MODULUS[2], d in 0..MODULUS[3]) -> Fr {
            Fr::from_repr(FrRepr([a, b, c, d])).unwrap()
        }
    }

    proptest!{
        #[test]
        fn sloth_roundtrip(key in arb_fr(), plaintext in arb_fr()) {
            let ciphertext = encode::<Bls12>(&key, &plaintext);
            assert_eq!(decode::<Bls12>(&key, &ciphertext), plaintext);
        }
    }
}
