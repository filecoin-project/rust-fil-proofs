use num_bigint::BigUint;
use pairing::bls12_381::Fr;
use pairing::Field;
use pairing::{PrimeField, PrimeFieldRepr};

fn big_from_fr(fr: &Fr) -> BigUint {
    let mut k = vec![];
    fr.into_repr().write_le(&mut k);
    BigUint::from_bytes_le(&k)
}

struct BlsSloth {}
impl BlsSloth {
    fn enc(key: &Fr, plaintext: &Fr) -> Fr {
        let (x, k) = (big_from_fr(plaintext), big_from_fr(key));

        let sloth_p = BigUint::parse_bytes(
            b"20974350070050476191779096203274386335076221000211055129041463479975432473805",
            10,
        ).unwrap();
        let sloth_v: BigUint = BigUint::parse_bytes(
            b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        ).unwrap();

        // Compute (x+k)^v mod p.
        let res = (x + k).modpow(&sloth_p, &sloth_v);

        let fr = Fr::from_str(&res.to_str_radix(10)).unwrap();
        fr
    }

    fn dec<'a>(key: &Fr, ciphertext: &Fr) -> Fr {
        let (c, k) = (ciphertext, key);

        let tmp = c;
        tmp.square();
        tmp.square();
        tmp.mul_assign(c);
        tmp.sub_assign(k);

        *tmp
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_sloth_bls_12() {
        // yolo();;;;
    }
}
