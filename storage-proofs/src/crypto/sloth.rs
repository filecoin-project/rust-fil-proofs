use algebra::PairingEngine as Engine;
use std::ops::AddAssign;
use std::ops::SubAssign;

/// Sloth based encoding.
#[inline]
pub fn encode<E: Engine>(key: &E::Fr, plaintext: &E::Fr) -> E::Fr {
    let mut ciphertext = *plaintext;

    ciphertext.add_assign(key); // c + k

    ciphertext
}

/// Sloth based decoding.
#[inline]
pub fn decode<E: Engine>(key: &E::Fr, ciphertext: &E::Fr) -> E::Fr {
    let mut plaintext = *ciphertext;

    plaintext.sub_assign(key); // c^5 - k

    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;

    use algebra::biginteger::BigInteger256 as FrRepr;
    use algebra::curves::bls12_377::Bls12_377 as Bls12;
    use algebra::fields::bls12_377::Fr;
    use algebra::fields::PrimeField;
    use std::str::FromStr;

    // the modulus from `bls12_377::Fr`
    // The definition of MODULUS comes from algebra/src/fields/bls12_377/fr.rs
    // MODULUS = 8444461749428370424248824938781546531375899335154063827935233455917409239041
    const MODULUS: [u64; 4] = [
        0x0a11800000000001,
        0x59aa76fed0000001,
        0x60b44d1e5c37b001,
        0x12ab655e9a2ca556,
    ];

    #[test]
    fn sloth_bls_12() {
        let key = Fr::from_str("11111111").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = encode::<Bls12>(&key, &plaintext);
        let decrypted = decode::<Bls12>(&key, &ciphertext);
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn sloth_bls_12_fake() {
        let key = Fr::from_str("11111111").unwrap();
        let key_fake = Fr::from_str("11111112").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = encode::<Bls12>(&key, &plaintext);
        let decrypted = decode::<Bls12>(&key_fake, &ciphertext);
        assert_ne!(plaintext, decrypted);
    }

    prop_compose! {
        fn arb_fr()(a in 0..MODULUS[0], b in 0..MODULUS[1], c in 0..MODULUS[2], d in 0..MODULUS[3]) -> Fr {
            Fr::from_repr(FrRepr([a, b, c, d]))
        }
    }
    proptest! {
        #[test]
        fn sloth_bls_roundtrip(key in arb_fr(), plaintext in arb_fr()) {
            let ciphertext = encode::<Bls12>(&key, &plaintext);
            assert_eq!(decode::<Bls12>(&key, &ciphertext), plaintext);
        }
    }
}
