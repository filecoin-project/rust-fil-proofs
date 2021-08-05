use blstrs::Scalar as Fr;

/// Sloth based encoding.
#[inline]
pub fn encode(key: &Fr, plaintext: &Fr) -> Fr {
    plaintext + key
}

/// Sloth based decoding.
#[inline]
pub fn decode(key: &Fr, ciphertext: &Fr) -> Fr {
    ciphertext - key
}

#[cfg(test)]
mod tests {
    use super::*;

    use ff::PrimeField;
    use proptest::{prop_compose, proptest};

    // the modulus from `bls12_381::Fr`
    // The definition of MODULUS and comment defining r come from blstrs/src/scalar.rs.
    // r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
    const MODULUS: [u64; 4] = [
        0xffffffff00000001,
        0x53bda402fffe5bfe,
        0x3339d80809a1d805,
        0x73eda753299d7d48,
    ];

    #[test]
    fn sloth_bls_12() {
        let key = Fr::from_str_vartime("11111111").expect("from_str failed");
        let plaintext = Fr::from_str_vartime("123456789").expect("from_str failed");
        let ciphertext = encode(&key, &plaintext);
        let decrypted = decode(&key, &ciphertext);
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn sloth_bls_12_fake() {
        let key = Fr::from_str_vartime("11111111").expect("from_str failed");
        let key_fake = Fr::from_str_vartime("11111112").expect("from_str failed");
        let plaintext = Fr::from_str_vartime("123456789").expect("from_str failed");
        let ciphertext = encode(&key, &plaintext);
        let decrypted = decode(&key_fake, &ciphertext);
        assert_ne!(plaintext, decrypted);
    }

    prop_compose! {
        fn arb_fr()(a in 0..MODULUS[0], b in 0..MODULUS[1], c in 0..MODULUS[2], d in 0..MODULUS[3]) -> Fr {
            let mut le_bytes = [0u8; 32];
            le_bytes[0..8].copy_from_slice(&a.to_le_bytes());
            le_bytes[8..16].copy_from_slice(&b.to_le_bytes());
            le_bytes[16..24].copy_from_slice(&c.to_le_bytes());
            le_bytes[24..32].copy_from_slice(&d.to_le_bytes());
            Fr::from_repr_vartime(le_bytes).expect("from_repr failed")
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
