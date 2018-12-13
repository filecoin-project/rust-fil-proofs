use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use num_traits::{One, Signed, Zero};
use rsa::math::{extended_gcd, ModInverse};

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

/// Calculates the `(xy)`-th root of `g`, given the `x`-th root and `y`-th root of `g.`
/// Operations are `mod n`.
pub fn shamir_trick(
    root_x: &BigUint,
    root_y: &BigUint,
    x: &BigUint,
    y: &BigUint,
    n: &BigUint,
) -> Option<BigUint> {
    // Check that the roots match to the same element
    let g1 = root_x.modpow(x, n);
    let g2 = root_y.modpow(y, n);

    if g1 != g2 {
        return None;
    }

    // a, b <- Bezout(x, y)
    let (_, a, b) = extended_gcd(x, y);

    let l = modpow_uint_int(&root_x, &b, n);
    let r = modpow_uint_int(&root_y, &a, n);

    if let Some(l) = l {
        if let Some(r) = r {
            return Some((l * r).mod_floor(n));
        }
    }

    None
}

/// Given `y = g^x` and `x = \prod x_i`, calculates the `x_i`-th roots, for all `i`.
/// All operations are `mod n`.
pub fn root_factor(g: &BigUint, x: &[BigUint], n: &BigUint) -> Vec<BigUint> {
    let m = x.len();
    if m == 1 {
        return vec![g.clone()];
    }

    let m_prime = m.div_floor(&2);

    let (x_l, x_r) = x.split_at(m_prime);

    let g_l = {
        let mut p = BigUint::one();
        // the paper uses the upper part for g_L
        for x in x_r {
            p *= x;
        }

        g.modpow(&p, n)
    };

    let g_r = {
        let mut p = BigUint::one();
        // the paper uses the lower part for g_R
        for x in x_l {
            p *= x;
        }

        g.modpow(&p, n)
    };

    let mut res = root_factor(&g_l, x_l, n);
    res.extend(root_factor(&g_r, x_r, n));

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_bigint::RandBigInt;
    use num_traits::{FromPrimitive, Pow};
    use rand::{thread_rng, Rng};
    use rsa::RandPrime;

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

    #[test]
    fn test_root_factor() {
        let mut rng = thread_rng();

        for _ in 0..10 {
            let n = rng.gen_biguint(64);
            let g = rng.gen_biguint(64);
            let m: usize = rng.gen_range(1, 128);

            let x = (0..m).map(|_| rng.gen_biguint(64)).collect::<Vec<_>>();

            let r = root_factor(&g, &x, &n);

            let mut xs = BigUint::one();
            for e in &x {
                xs *= e;
            }
            let y = g.modpow(&xs, &n);

            for (root, x_i) in r.iter().zip(x.iter()) {
                // root is the x_i-th root of y
                // so we check that root^x_i = y
                assert_eq!(&root.clone().modpow(x_i, &n), &y);
            }
        }
    }

    #[test]
    fn test_shamir_trick() {
        let mut rng = thread_rng();

        for _ in 0..30 {
            let n = rng.gen_biguint(64);
            let g = rng.gen_prime(64);

            let x = rng.gen_prime(64);
            let y = rng.gen_prime(64);
            let z = rng.gen_prime(64);

            // the element we calc the root against
            let a = g.modpow(&(x.clone() * &y * &z), &n);
            let root_x = g.modpow(&(y.clone() * &z), &n);
            let root_y = g.modpow(&(x.clone() * &z), &n);

            // make sure they are actual roots
            assert_eq!(
                &root_x.modpow(&x, &n),
                &a,
                "root_x is not the x-th root of a"
            );
            assert_eq!(
                &root_y.modpow(&y, &n),
                &a,
                "root_y is not the y-th root of a"
            );

            let root = shamir_trick(&root_x, &root_y, &x, &y, &n).unwrap();

            // root is the xy-th root of a
            // so we check that root^xy = a
            assert_eq!(&root.clone().modpow(&(x.clone() * &y), &n), &a);
        }
    }
}
