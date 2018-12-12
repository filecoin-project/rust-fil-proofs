use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use rsa::math::ModInverse;

/// Calculates a = a.pow(b).
// TODO: this can be speed up using various techniques, like precomputations.
pub fn pow_assign(a: &mut BigUint, b: &BigUint) {
    if b.is_zero() {
        *a = BigUint::one();
    } else if b.is_odd() {
        let a_before = a.clone();
        pow_assign(a, &(b.clone() - 1u32));
        *a *= &a_before;
    } else {
        pow_assign(a, &(b.clone() / 2u32));
        *a *= a.clone();
    }
}

/// Calculates a ^ e % n.
pub fn modpow_uint_int(a: &BigUint, e: &BigInt, n: &BigUint) -> Option<BigUint> {
    match e.sign() {
        Sign::Plus => {
            // regular case
            Some(a.clone().modpow(&e.to_biguint().unwrap(), n))
        }
        Sign::Minus => {
            // exponent is negative, so we calculate the modular inverse of e.
            let a_signed = BigInt::from_biguint(Sign::Plus, a.clone());
            let n_signed = BigInt::from_biguint(Sign::Plus, n.clone());

            if let Some(a_inv) = a_signed.mod_inverse(&n_signed) {
                let e_abs = e.abs().to_biguint().unwrap();
                Some(a_inv.to_biguint().unwrap().modpow(&e_abs, n))
            } else {
                None
            }
        }
        Sign::NoSign => {
            // zero
            Some(BigUint::one())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_traits::{FromPrimitive, Pow};

    #[test]
    fn test_pow_assign_basics() {
        for i in 0..1024 {
            for j in 0..128 {
                let res = BigUint::from_usize(i).unwrap().pow(j as u32);
                let mut res_big = BigUint::from_usize(i).unwrap();
                pow_assign(&mut res_big, &BigUint::from_usize(j).unwrap());
                assert_eq!(res_big, res);
            }
        }
    }

    #[test]
    fn test_quo_rem() {
        // Ref: https://www.wolframalpha.com/input/?i=QuotientRemainder%5B-10,+13%5D
        let (l, r) = &BigInt::from_i64(-10)
            .unwrap()
            .div_mod_floor(&BigInt::from_i64(13).unwrap());

        assert_eq!(
            (l, r),
            (
                &BigInt::from_i64(-1).unwrap(),
                &BigInt::from_i64(3).unwrap(),
            )
        );
    }

    #[test]
    fn test_modpow() {
        let cases = vec![["49", "-6193420858199668535", "2881", "6"]];

        for case in &cases {
            let a = BigUint::parse_bytes(case[0].as_bytes(), 10).unwrap();
            let e = BigInt::parse_bytes(case[1].as_bytes(), 10).unwrap();
            let n = BigUint::parse_bytes(case[2].as_bytes(), 10).unwrap();
            let expected = BigUint::parse_bytes(case[3].as_bytes(), 10).unwrap();

            let actual = modpow_uint_int(&a, &e, &n).unwrap();

            assert_eq!(expected, actual);
        }
    }
}
