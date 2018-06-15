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

trait Sloth {
    type T;
    type Err;

    fn enc<'a>(
        key: &Self::T,
        plaintext: &Self::T,
        p: &Self::T,
        v: &Self::T,
    ) -> Result<Self::T, Self::Err>;

    fn dec<'a>(
        key: &Self::T,
        ciphertext: &Self::T,
        p: &Self::T,
        v: &Self::T,
        exp: &Self::T,
    ) -> Result<Self::T, Self::Err>;
}

struct IntSloth {}
impl Sloth for IntSloth {
    type T = BigUint;
    type Err = ();

    fn enc(
        key: &BigUint,
        plaintext: &BigUint,
        p: &BigUint,
        v: &BigUint,
    ) -> Result<BigUint, Self::Err> {
        let (x, k) = (plaintext, key);

        // Compute (x+k)^v mod p.
        Ok((x + k).modpow(&v, &p))
    }

    fn dec<'a>(
        key: &BigUint,
        ciphertext: &BigUint,
        p: &BigUint,
        v: &BigUint,
        exp: &BigUint,
    ) -> Result<BigUint, Self::Err> {
        let (c, k) = (ciphertext, key);

        // Compute c^exp - k mod p
        Ok((c.modpow(exp, &p) - k).mod_floor(&p))
    }
}

fn dec(key: &Fr, ciphertext: &Fr, p: &Fr, v: &Fr, exp: &Fr) -> Result<Fr, PrimeFieldDecodingError> {
    unimplemented!();
}

fn big(x: u64) -> BigUint {
    BigUint::from_u64(x).unwrap()
}

// For later use…
fn to_fr(n: u64) -> Fr {
    Fr::from_repr(<Fr as PrimeField>::Repr::from(n)).unwrap()
}

fn sloth_enc(key: &BigUint, plaintext: &BigUint, p: &BigUint, v: &BigUint) -> BigUint {
    IntSloth::enc(key, plaintext, p, v).unwrap()
}

fn big_from_fr(fr: &Fr) -> BigUint {
    let mut k = vec![];
    fr.into_repr().write_le(&mut k);
    BigUint::from_bytes_le(&k)
}

fn fr_from_bytes(bytes: &[u8]) -> Fr {
    let mut u = [0u64; 4];

    for i in 0..4 {
        let mut acc: u64 = 0;
        for j in 0..4 {
            acc <<= 8;
            let index = (i * 4) + (3 - j);
            let byte = if index >= bytes.len() {
                0
            } else {
                bytes[index]
            };
            acc += byte as u64;
        }
        u[3 - i] = acc;
        acc = 0;
    }

    fr_from_u64s(u)
}

fn fr_from_u64s(u64s: [u64; 4]) -> Fr {
    let mut acc = to_fr(0u64);

    let mut xxx = to_fr(0xffffu64);
    xxx.add_assign(&to_fr(1));

    for u in u64s.iter() {
        let bf = to_fr(*u);
        acc.mul_assign(&xxx);
        acc.add_assign(&bf);
    }
    acc
}

fn sloth_enc_fr(key: &Fr, plaintext: &Fr) -> Fr {
    let k = big_from_fr(key);
    let x = big_from_fr(plaintext);
    let sloth_p = BigUint::parse_bytes(
        b"20974350070050476191779096203274386335076221000211055129041463479975432473805",
        10,
    ).unwrap();
    let sloth_v: BigUint = BigUint::parse_bytes(
        b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
        10,
    ).unwrap();
    let res = IntSloth::enc(&k, &x, &sloth_p, &sloth_v).unwrap();
    let bytes = res.to_bytes_le();

    *key
}

fn sloth_dec<'a>(
    key: &BigUint,
    ciphertext: &BigUint,
    p: &BigUint,
    v: &BigUint,
    exp: &BigUint,
) -> BigUint {
    IntSloth::dec(key, ciphertext, p, v, exp).unwrap()
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
    fn test_biguint_bytes() {
        let b = BigUint::from(0u64);
        let bytes = b.to_bytes_le();

        println!("bytes: {:?}", bytes);

        let fr = FrRepr::from(123456789u64);
        println!("fr: {:?}", fr);

        let sloth_p = BigUint::parse_bytes(
            b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        ).unwrap();
        let p_bytes = BigUint::to_bytes_le(&sloth_p);
        let p_fr = fr_from_bytes(&p_bytes);
        println!("p_fr: {:?}", p_fr);

        println!(
            "MODULUS: {:?}",
            FrRepr([
                0xffffffff00000001,
                0x53bda402fffe5bfe,
                0x3339d80809a1d805,
                0x73eda753299d7d48,
            ])
        );
        let xxx = BigUint::parse_bytes(b"123", 10).unwrap();
        let xxx_bytes = fr_from_bytes(&BigUint::to_bytes_le(&xxx));
        println!("xxx: {:?}", xxx_bytes);
    }

    #[test]
    fn test_sloth_good_params() {
        // These params are from the original Go implementation and are known good.
        let p = b"135741874269561010210788515394321418560783524050838812444665528300130001644649";
        let v = b"90494582846374006807192343596214279040522349367225874963110352200086667763099";
        sloth_enc_dec_many(p, v, big(3));
    }

    #[test]
    fn test_sloth_bls_12() {
        // p is bls12 as given
        let p = b"52435875175126190479447740508185965837690552500527637822603658699938581184513";
        // v is computed. NOTE: this fails in Go too, so seems to be wrong.
        let v = b"20974350070050476191779096203274386335076221000211055129041463479975432473805";
        sloth_enc_dec_many(p, v, big(5));
    }
}
