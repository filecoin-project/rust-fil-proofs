use blake2::Blake2b;
use num_bigint::BigUint;
use num_integer::Integer;

use crate::hash::hash_prime;

/// NI-PoE Prove
/// Assumes `u^x = w`
/// All operations are `mod n`.
pub fn ni_poe_prove(x: &BigUint, u: &BigUint, w: &BigUint, n: &BigUint) -> BigUint {
    debug_assert!(&u.modpow(x, n) == w, "invalid input");

    // l <- H_prime(x, u, w)
    let mut to_hash = x.to_bytes_be();
    to_hash.extend(&u.to_bytes_be());
    to_hash.extend(&w.to_bytes_be());

    let l = hash_prime::<_, Blake2b>(&to_hash);

    // q <- floor(x/l)
    let q = x.div_floor(&l);

    // r <- x mod l
    // this is not used, why do we calculate it?
    // let r = x.mod_floor(&l);

    // Q <- u^q
    u.modpow(&q, n)
}

/// NI-PoE Verify
/// Assumes `u^x = w`
/// All operations are `mod n`.
pub fn ni_poe_verify(x: &BigUint, u: &BigUint, w: &BigUint, q: &BigUint, n: &BigUint) -> bool {
    debug_assert!(&u.modpow(x, n) == w, "invalid input");

    // l <- H_prime(x, u, w)
    let mut to_hash = x.to_bytes_be();
    to_hash.extend(&u.to_bytes_be());
    to_hash.extend(&w.to_bytes_be());

    let l = hash_prime::<_, Blake2b>(&to_hash);

    // r <- x mod l
    let r = x.mod_floor(&l);

    // Q^l u^r == w
    &(q.modpow(&l, &n) * &u.modpow(&r, &n)).mod_floor(&n) == w
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_bigint::RandBigInt;
    use rand::thread_rng;
    use rsa::RandPrime;

    #[test]
    fn test_ni_poe() {
        let mut rng = thread_rng();

        for _ in 0..10 {
            let n = rng.gen_biguint(128);

            let x = rng.gen_prime(512);
            let u = rng.gen_prime(128);
            let w = u.modpow(&x, &n);

            let q = ni_poe_prove(&x, &u, &w, &n);
            assert!(ni_poe_verify(&x, &u, &w, &q, &n))
        }
    }
}
