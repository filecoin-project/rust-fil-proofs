use num_bigint::BigUint;
use pairing::bls12_381::Fr;
use pairing::Field;
use pairing::{PrimeField, PrimeFieldRepr};

lazy_static! {
    static ref SLOTH_V: BigUint = BigUint::parse_bytes(
        b"20974350070050476191779096203274386335076221000211055129041463479975432473805",
        10,
    ).unwrap();
    static ref SLOTH_P: BigUint = BigUint::parse_bytes(
        b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
        10,
    ).unwrap();
}

fn big_from_fr(fr: &Fr) -> BigUint {
    let mut k = vec![];
    fr.into_repr().write_le(&mut k).unwrap();
    BigUint::from_bytes_le(&k)
}

struct BlsSloth {}
impl BlsSloth {
    fn enc(key: &Fr, plaintext: &Fr) -> Fr {
        let (x, k) = (big_from_fr(plaintext), big_from_fr(key));

        // Compute (x+k)^v mod p.
        let res = (x + k).modpow(&SLOTH_V, &SLOTH_P);

        // TODO: this can be done more efficiently
        let fr = Fr::from_str(&res.to_str_radix(10)).unwrap();
        fr
    }

    fn dec<'a>(key: &Fr, ciphertext: &Fr) -> Fr {
        let (c, k) = (ciphertext, key);

        let mut tmp = c.clone();
        tmp.square(); // c^2
        tmp.square(); // (c^2)^2
        tmp.mul_assign(c); // (c^2)^2 * c = c^5
        tmp.sub_assign(k);

        tmp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Fr;
    #[test]
    fn test_sloth_bls_12() {
        let key = Fr::from_str("11111111").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = BlsSloth::enc(&key, &plaintext);
        let decrypted = BlsSloth::dec(&key, &ciphertext);
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, ciphertext);
    }

    #[test]
    fn test_sloth_bls_12_fake() {
        let key = Fr::from_str("11111111").unwrap();
        let key_fake = Fr::from_str("11111112").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = BlsSloth::enc(&key, &plaintext);
        let decrypted = BlsSloth::dec(&key_fake, &ciphertext);
        assert_ne!(plaintext, decrypted);
    }
}
