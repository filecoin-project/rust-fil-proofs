use bellperson::bls::Fr;
use ff::Field;

/// Sloth based encoding.
#[inline]
pub fn encode(key: &Fr, plaintext: &Fr) -> Fr {
    let mut ciphertext = *plaintext;

    ciphertext.add_assign(key); // c + k
    ciphertext
}

/// Sloth based decoding.
#[inline]
pub fn decode(key: &Fr, ciphertext: &Fr) -> Fr {
    let mut plaintext = *ciphertext;

    plaintext.sub_assign(key); // c - k

    plaintext
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::bls::{Fr, FrRepr};
    use ff::PrimeField;
    use proptest::{prop_compose, proptest};

    // the modulus from `bls12_381::Fr`
    // The definition of MODULUS and comment defining r come from paired/src/bls_12_381/fr.rs.
    // r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
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
        let ciphertext = encode(&key, &plaintext);
        let decrypted = decode(&key, &ciphertext);
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn sloth_bls_12_fake() {
        let key = Fr::from_str("11111111").unwrap();
        let key_fake = Fr::from_str("11111112").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = encode(&key, &plaintext);
        let decrypted = decode(&key_fake, &ciphertext);
        assert_ne!(plaintext, decrypted);
    }

    prop_compose! {
        fn arb_fr()(a in 0..MODULUS[0], b in 0..MODULUS[1], c in 0..MODULUS[2], d in 0..MODULUS[3]) -> Fr {
            Fr::from_repr(FrRepr([a, b, c, d])).unwrap()
        }
    }
    proptest! {
        #[test]
        fn sloth_bls_roundtrip(key in arb_fr(), plaintext in arb_fr()) {
            let ciphertext = encode(&key, &plaintext);
            assert_eq!(decode(&key, &ciphertext), plaintext);
        }
    }
}
