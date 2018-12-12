use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::One;
use rand::OsRng;
use rsa::math::extended_gcd;

use crate::math::modpow_uint_int;
use crate::primes::generate_primes;

pub trait StaticAccumulator {
    /// Setup generates a group of unknown order and initializes the group
    /// with a generator of that group.
    fn setup(lambda: usize) -> Self;

    /// Update the accumulator.
    fn add(&mut self, x: &BigUint);

    /// Create a membership proof.
    /// Returns `None`, iff `x` is not a member.
    fn mem_wit_create(&self, x: &BigUint) -> BigUint;

    /// Verify a membership proof.
    fn ver_mem(&self, w: &BigUint, x: &BigUint) -> bool;
}

pub trait DynamicAccumulator: StaticAccumulator {
    /// Delete a value from the accumulator.
    fn del(&mut self, x: &BigUint);
}

pub trait UniversalAccumulator: DynamicAccumulator {
    /// Create a non-membership proof.
    /// Returns `None`, iff `x` is a member.
    fn non_mem_wit_create(&self, x: &BigUint) -> (BigUint, BigInt);

    /// Verify a non-membership proof.
    fn ver_non_mem(&self, w: &(BigUint, BigInt), x: &BigUint) -> bool;
}

pub struct RsaAccumulator {
    lambda: usize,
    /// Generator
    g: BigUint,
    /// n = pq
    n: BigUint,

    // current accumulator state
    a_t: BigUint,

    // prod of the current set
    s: BigUint,
}

impl RsaAccumulator {
    /// Internal method to recalculate `a_t`, based on the current of `s`.
    fn update(&mut self) {
        self.a_t = self.g.clone().modpow(&self.s, &self.n);
    }
}

impl StaticAccumulator for RsaAccumulator {
    fn setup(lambda: usize) -> Self {
        println!("setup({})", lambda);
        // Generate n = p q, |n| = lambda
        // This is a trusted setup, as we do know `p` and `q`, even though
        // we choose not to store them.

        let mut rng = OsRng::new().unwrap();
        let (n, _, _, g) = generate_primes(&mut rng, lambda).unwrap();

        RsaAccumulator {
            lambda,
            a_t: g.clone(),
            g,
            n,
            s: BigUint::one(),
        }
    }

    fn add(&mut self, x: &BigUint) {
        println!("add({})", x);
        // assumes x is already primes
        self.s *= x;
        self.update();
    }

    fn mem_wit_create(&self, x: &BigUint) -> BigUint {
        println!("mem_wit_create({})", x);

        let s = self.s.clone() / x;
        self.g.clone().modpow(&s, &self.n)
    }

    fn ver_mem(&self, w: &BigUint, x: &BigUint) -> bool {
        println!("ver_mem({}, {})", w, x);
        w.modpow(x, &self.n) == self.a_t
    }
}

impl DynamicAccumulator for RsaAccumulator {
    fn del(&mut self, x: &BigUint) {
        println!("del({})", x);

        self.s /= x;
        self.update();
    }
}

impl UniversalAccumulator for RsaAccumulator {
    fn non_mem_wit_create(&self, x: &BigUint) -> (BigUint, BigInt) {
        println!("non_mem_wit_create({})", x);

        // s* <- \prod_{s\in S} s
        let s_star = &self.s;

        // a, b <- Bezout(x, s*)
        let (_, a, b) = extended_gcd(x, s_star);
        let d = modpow_uint_int(&self.g, &a, &self.n).expect("prime");

        (d, b)
    }

    fn ver_non_mem(&self, w: &(BigUint, BigInt), x: &BigUint) -> bool {
        println!("ver_non_mem(({}, {}), {})", w.0, w.1, x);
        let (d, b) = w;

        // A^b
        let a_b = modpow_uint_int(&self.a_t, b, &self.n).expect("prime");
        // d^x
        let d_x = d.modpow(x, &self.n);

        // d^x A^b == g
        (d_x * &a_b).mod_floor(&self.n) == self.g
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_bigint::Sign;
    use num_integer::Integer;
    use num_traits::FromPrimitive;
    use rand::{thread_rng, SeedableRng, XorShiftRng};
    use rsa::RandPrime;

    #[test]
    fn test_static() {
        let mut rng = thread_rng();

        for _ in 0..100 {
            let lambda = 256; // insecure, but faster tests
            let mut acc = RsaAccumulator::setup(lambda);

            let xs = (0..5).map(|_| rng.gen_prime(lambda)).collect::<Vec<_>>();

            for x in &xs {
                acc.add(x);
            }

            for x in &xs {
                let w = acc.mem_wit_create(x);
                assert!(acc.ver_mem(&w, x));
            }
        }
    }

    #[test]
    fn test_dynamic() {
        let mut rng = thread_rng();

        for _ in 0..20 {
            let lambda = 256; // insecure, but faster tests
            let mut acc = RsaAccumulator::setup(lambda);

            let xs = (0..5).map(|_| rng.gen_prime(lambda)).collect::<Vec<_>>();

            for x in &xs {
                acc.add(x);
            }

            let ws = xs
                .iter()
                .map(|x| {
                    let w = acc.mem_wit_create(x);
                    assert!(acc.ver_mem(&w, x));
                    w
                })
                .collect::<Vec<_>>();

            for (x, w) in xs.iter().zip(ws.iter()) {
                // remove x
                acc.del(x);
                // make sure test now fails
                assert!(!acc.ver_mem(w, x));
            }
        }
    }

    #[test]
    fn test_universal() {
        let mut rng = thread_rng();

        for _ in 0..20 {
            let lambda = 256; // insecure, but faster tests
            let mut acc = RsaAccumulator::setup(lambda);

            let xs = (0..5).map(|_| rng.gen_prime(lambda)).collect::<Vec<_>>();

            for x in &xs {
                acc.add(x);
            }

            for _ in 0..5 {
                let y = rng.gen_prime(lambda);

                let w = acc.non_mem_wit_create(&y);
                assert!(acc.ver_non_mem(&w, &y));
            }
        }
    }

    #[test]
    fn test_math_non_mempership() {
        let rng = &mut XorShiftRng::from_seed([0u8; 16]);

        let lambda = 32;

        let x = rng.gen_prime(lambda);
        let s1 = rng.gen_prime(lambda);
        let s2 = rng.gen_prime(lambda);

        let n = BigUint::from_u32(43 * 67).unwrap();
        let g = BigUint::from_u32(49).unwrap();

        // s* = \prod s
        let mut s_star = BigUint::one();
        s_star *= &s1;
        s_star *= &s2;

        // A = g ^ s*
        let a_t = g.modpow(&s_star, &n);

        let (_, a, b) = extended_gcd(&x, &s_star);
        println!("{} {} {} {}", &g, &a, &b, &n);

        let u = BigInt::from_biguint(Sign::Plus, x.clone());
        let v = BigInt::from_biguint(Sign::Plus, s_star);
        let lhs = a.clone() * &u;
        let rhs = b.clone() * &v;
        println!("> {} * {} + {} * {} == 1", &a, &u, &b, &v);
        assert_eq!(lhs + &rhs, BigInt::one());

        // d = g^a mod n
        let d = modpow_uint_int(&g, &a, &n).unwrap();
        println!("> {} = {}^{} mod {}", &d, &g, &a, &n);

        // A^b
        let a_b = modpow_uint_int(&a_t, &b, &n).unwrap();
        println!("> {} = {}^{} mod {}", &a_b, &a_t, &b, &n);

        // A^b == g^{s* * b}
        let res = modpow_uint_int(&g, &(&v * &b), &n).unwrap();
        println!("> {} = {}^({} * {}) mod {}", &res, &g, &v, &b, &n);
        assert_eq!(a_b, res);

        // d^x
        let d_x = d.modpow(&x, &n);
        println!("> (d_x) {} = {}^{} mod {}", &d_x, &d, &x, &n);

        // d^x == g^{a * x}
        let res = modpow_uint_int(&g, &(&a * &u), &n).unwrap();
        println!("> (d_x) {} = {}^({} * {}) mod {}", &res, &g, &a, &u, &n);
        assert_eq!(d_x, res);

        // d^x A^b == g
        let lhs = (&d_x * &a_b).mod_floor(&n);
        println!("> {} = {} * {} mod {}", &lhs, &d_x, &a_b, &n);
        assert_eq!(lhs, g);
    }
}
