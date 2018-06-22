use pairing::{Engine, Field};

pub const DEFAULT_ROUNDS: usize = 1;

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

/// Sloth based encoding.
pub fn encode<E: Engine>(key: &E::Fr, plaintext: &E::Fr, rounds: usize) -> E::Fr {
    let mut ciphertext = *plaintext;

    for _ in 0..rounds {
        ciphertext.add_assign(key); // c + k
        ciphertext = ciphertext.pow(&SLOTH_V) // (c + k)^v
    }

    ciphertext
}

/// Sloth based decoding.
pub fn decode<E: Engine>(key: &E::Fr, ciphertext: &E::Fr, rounds: usize) -> E::Fr {
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
        let ciphertext = encode::<Bls12>(&key, &plaintext, 10);
        let decrypted = decode::<Bls12>(&key, &ciphertext, 10);
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn sloth_bls_12_fake() {
        let key = Fr::from_str("11111111").unwrap();
        let key_fake = Fr::from_str("11111112").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = encode::<Bls12>(&key, &plaintext, 10);
        let decrypted = decode::<Bls12>(&key_fake, &ciphertext, 10);
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
            let ciphertext = encode::<Bls12>(&key, &plaintext, 10);
            assert_eq!(decode::<Bls12>(&key, &ciphertext, 10), plaintext);
        }
    }
}
