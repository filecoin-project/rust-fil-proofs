use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::cast::FromPrimitive;
use pairing::bls12_381::Bls12;
use pairing::bls12_381::{Fr, FrRepr};
use pairing::{Engine, Field};
use pairing::{PrimeField, PrimeFieldDecodingError, PrimeFieldRepr, SqrtField};

fn big_from_u64(x: u64) -> BigUint {
    match BigUint::from_u64(x) {
        Some(b) => b,
        None => panic!(),
    }
}

// For later use…
fn to_fr(n: u64) -> Result<Fr, PrimeFieldDecodingError> {
    Fr::from_repr(<Fr as PrimeField>::Repr::from(n))
}

fn sloth_enc(key: &BigUint, plaintext: &BigUint, p: &BigUint, v: &BigUint) -> BigUint {
    let (x, k) = (plaintext, key);

    // Compute (x+k)^v mod p.
    (x + k).modpow(&v, &p)
}

fn sloth_dec<'a>(
    key: &BigUint,
    ciphertext: BigUint,
    p: &BigUint,
    v: &BigUint,
    exp: &BigUint,
) -> BigUint {
    let (c, k) = (ciphertext, key);

    println!("exp: {:?}", exp);
    // Compute c^exp - k mod p
    (c.modpow(exp, &p) - k).mod_floor(&p)
}

fn sloth_enc_fr(key: Fr, plaintext: Fr, v: &[u64]) -> Result<Fr, PrimeFieldDecodingError> {
    unimplemented!();
}

fn sloth_dec_x<'a>(key: Fr, ciphertext: Fr, v: &[u64]) -> Result<Fr, PrimeFieldDecodingError> {
    unimplemented!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sloth_enc_dec(key: u64, plaintext: u64, p: BigUint, v: BigUint, exp: BigUint) {
        let k = big_from_u64(key);
        let k_copy = k.clone();
        let pt = big_from_u64(plaintext);
        let pt_copy = pt.clone();
        let encrypted = sloth_enc(&k, &pt, &p, &v);
        assert_ne!(
            pt_copy, encrypted,
            "ciphertext and plain text should not be equal"
        );

        let decrypted = sloth_dec(&k_copy, encrypted, &p, &v, &exp);
        assert_eq!(
            pt_copy, decrypted,
            "decrypted ciphertext must equal plaintext"
        );
    }

    fn sloth_enc_dec_many(p_bytes: &[u8], v_bytes: &[u8], exp: BigUint) {
        let p = BigUint::parse_bytes(p_bytes, 10).unwrap();
        let v = BigUint::parse_bytes(v_bytes, 10).unwrap();

        let z = BigUint::parse_bytes(b"1234567890123", 10);
        // TODO: Add more test cases. Check Go source.
        sloth_enc_dec(12345, 98765, p, v, exp);
    }

    #[test]
    fn test_sloth_good_params() {
        // These params are from the original Go implementation and are known good.
        let p = b"135741874269561010210788515394321418560783524050838812444665528300130001644649";
        let v = b"90494582846374006807192343596214279040522349367225874963110352200086667763099";
        sloth_enc_dec_many(p, v, big_from_u64(3));
    }

    #[test]
    fn test_sloth_bls_12() {
        // p is bls12 as given
        let p = b"52435875175126190479447740508185965837690552500527637822603658699938581184513";
        // v is computed. NOTE: this fails in Go too, so seems to be wrong.
        let v = b"20974350070050476191779096203274386335076221000211055129041463479975432473804";
        sloth_enc_dec_many(p, v, big_from_u64(5));
    }
}
