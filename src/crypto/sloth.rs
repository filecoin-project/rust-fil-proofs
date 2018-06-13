use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::cast::FromPrimitive;
use pairing::bls12_381::Bls12;
use pairing::bls12_381::{Fr, FrRepr};
use pairing::{Engine, Field};
use pairing::{PrimeField, PrimeFieldDecodingError, PrimeFieldRepr, SqrtField};

lazy_static! {
    static ref ONE: BigUint = BigUint::from(1 as u64);
    static ref TWO: BigUint = BigUint::from(1 as u64);
}

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
    ciphertext: &BigUint,
    p: &BigUint,
    v: &BigUint,
    exp: &BigUint,
) -> BigUint {
    let (c, k) = (ciphertext, key);

    // Compute c^exp - k mod p
    (c.modpow(exp, &p) - k).mod_floor(&p)
}

fn sloth_enc_fr(key: Fr, plaintext: Fr, v: &[u64]) -> Result<Fr, PrimeFieldDecodingError> {
    unimplemented!();
}

fn sloth_dec_x<'a>(key: Fr, ciphertext: Fr, v: &[u64]) -> Result<Fr, PrimeFieldDecodingError> {
    unimplemented!();
}

fn sloth_enc_bytes_by_chunk(
    key: &BigUint,
    plaintext: &[u8],
    p: &BigUint,
    v: &BigUint,
    chunk_size: usize,
) -> Vec<u8> {
    let capacity = bytes_capacity(p);
    assert!(chunk_size <= capacity);
    assert!(bytes_needed(key) <= capacity);
    let out_size = bytes_needed(p);
    plaintext
        .chunks(chunk_size)
        .flat_map(|chunk| {
            let plaintext_chunk = BigUint::from_bytes_le(chunk);
            let mut enc = sloth_enc(key, &plaintext_chunk, p, v).to_bytes_le();
            let padding_size = out_size - enc.len();
            for i in 0..padding_size {
                enc.push(0);
            }
            if enc.len() != out_size {
                unreachable!("encoded chunk wrong size");
            };
            enc
        })
        .collect()
}

fn sloth_enc_bytes(key: &[u8], plaintext: &[u8], p: &BigUint, v: &BigUint) -> Vec<u8> {
    let capacity = bytes_capacity(p);
    let key = BigUint::from_bytes_le(key);
    assert!(bytes_needed(&key) <= capacity);
    let chunk_size = capacity;
    sloth_enc_bytes_by_chunk(&key, plaintext, p, v, chunk_size)
}

fn sloth_dec_bytes_by_chunk(
    key: &BigUint,
    ciphertext: &[u8],
    p: &BigUint,
    v: &BigUint,
    exp: &BigUint,
    chunk_size: usize,
) -> Vec<u8> {
    let in_size = bytes_needed(p);
    let capacity = bytes_capacity(p);
    assert!(chunk_size <= in_size);
    assert!(bytes_needed(&key) <= capacity);
    ciphertext
        .chunks(chunk_size)
        .flat_map(|chunk| {
            let ciphertext_chunk = BigUint::from_bytes_le(chunk);
            let dec = sloth_dec(&key, &ciphertext_chunk, p, v, exp).to_bytes_le();
            dec
        })
        .collect()
}

fn sloth_dec_bytes(
    key: &[u8],
    plaintext: &[u8],
    p: &BigUint,
    v: &BigUint,
    exp: &BigUint,
) -> Vec<u8> {
    let capacity = bytes_capacity(p);
    let needed = bytes_needed(p);
    let key = BigUint::from_bytes_le(key);
    assert!(bytes_needed(&key) <= capacity);
    let chunk_size = needed;
    sloth_dec_bytes_by_chunk(&key, plaintext, p, v, exp, chunk_size)
}

fn bytes_capacity(p: &BigUint) -> usize {
    p.bits() / 8
}

fn bytes_needed(p: &BigUint) -> usize {
    let bits = p.bits();
    let needed = if (bits % 8 == 0) {
        bits / 8
    } else {
        (bits + 7) / 8
    };
    needed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sloth_enc_dec(key: &[u8], plaintext: &[u8], p: &BigUint, v: &BigUint, exp: &BigUint) {
        let k = BigUint::from_bytes_le(key);
        let k_copy = k.clone();
        let pt = BigUint::from_bytes_le(plaintext);
        let pt_copy = pt.clone();
        let encrypted = sloth_enc(&k, &pt, p, v);
        assert_ne!(
            pt_copy, encrypted,
            "ciphertext and plain text should not be equal"
        );

        let decrypted = sloth_dec(&k_copy, &encrypted, p, v, exp);
        assert_eq!(
            pt_copy, decrypted,
            "decrypted ciphertext must equal plaintext"
        );
    }

    fn sloth_enc_dec_bytes(key: &[u8], plaintext: &[u8], p: &BigUint, v: &BigUint, exp: &BigUint) {
        let k = b"thekey";
        let encrypted = sloth_enc_bytes(key, plaintext, p, v);
        assert_ne!(&encrypted, &plaintext);

        // TODO: Add tests more explicitly establishing the expected length of ciphertext.
        assert!(&encrypted.len() >= &plaintext.len());
        let decrypted = sloth_dec_bytes(key, &encrypted, p, v, exp);
        assert_eq!(&decrypted, &plaintext);
    }

    fn sloth_enc_dec_many(p_bytes: &[u8], v_bytes: &[u8], exp: BigUint) {
        let p = BigUint::parse_bytes(p_bytes, 10).unwrap();
        let v = BigUint::parse_bytes(v_bytes, 10).unwrap();

        let z = BigUint::parse_bytes(b"1234567890123", 10);
        // TODO: Add more test cases. Check Go source.
        sloth_enc_dec(b"key", b"short", &p, &v, &exp);
        sloth_enc_dec_bytes(
            b"key",
            b"The text is so very plain, and it's long enough to need chunking.",
            &p,
            &v,
            &exp,
        );
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
        let v = b"20974350070050476191779096203274386335076221000211055129041463479975432473805";
        sloth_enc_dec_many(p, v, big_from_u64(5));
    }
}
