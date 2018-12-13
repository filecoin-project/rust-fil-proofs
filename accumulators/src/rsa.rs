use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::One;
use rand::OsRng;
use rsa::math::extended_gcd;

use crate::math::{modpow_uint_int, root_factor, shamir_trick};
use crate::primes::generate_primes;
use crate::proofs;
use crate::traits::*;

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

    /// Returns the current public state.
    pub fn state(&self) -> &BigUint {
        &self.a_t
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
    fn del(&mut self, x: &BigUint) -> Option<()> {
        println!("del({})", x);

        let old_s = self.s.clone();
        self.s /= x;

        if self.s == old_s {
            return None;
        }

        self.update();
        Some(())
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

impl BatchedAccumulator for RsaAccumulator {
    fn batch_add(&mut self, xs: &[BigUint]) -> BigUint {
        println!("batch_add({:?})", xs);
        let mut x_star = BigUint::one();
        for x in xs {
            x_star *= x
        }

        let a_t = self.a_t.clone();
        self.add(&x_star);

        proofs::ni_poe_prove(&x_star, &a_t, &self.a_t, &self.n)
    }

    fn ver_batch_add(&self, w: &BigUint, a_t: &BigUint, xs: &[BigUint]) -> bool {
        println!("ver_batch_add({} - {} - {:?})", w, a_t, xs);
        let mut x_star = BigUint::one();
        for x in xs {
            x_star *= x
        }

        proofs::ni_poe_verify(&x_star, a_t, &self.a_t, &w, &self.n)
    }

    fn batch_del(&mut self, pairs: &[(BigUint, BigUint)]) -> Option<BigUint> {
        println!("batch_del({:?})", pairs);
        if pairs.is_empty() {
            return None;
        }
        let mut pairs = pairs.iter();
        let a_t = self.a_t.clone();

        let (x0, w0) = pairs.next().unwrap();
        let mut x_star = x0.clone();
        let mut new_a_t = w0.clone();

        for (xi, wi) in pairs {
            println!("removing {}", xi);
            new_a_t = shamir_trick(&new_a_t, wi, &x_star, xi, &self.n).unwrap();
            x_star *= xi;
            // for now this is not great, depends on this impl, not on the general design
            self.s /= xi;
        }

        self.a_t = new_a_t;

        Some(proofs::ni_poe_prove(&x_star, &self.a_t, &a_t, &self.n))
    }

    fn ver_batch_del(&self, w: &BigUint, a_t: &BigUint, xs: &[BigUint]) -> bool {
        println!("ver_batch_del({} - {} - {:?})", w, a_t, xs);
        let mut x_star = BigUint::one();
        for x in xs {
            x_star *= x
        }

        proofs::ni_poe_verify(&x_star, &self.a_t, a_t, &w, &self.n)
    }

    fn del_w_mem(&mut self, w: &BigUint, x: &BigUint) -> Option<()> {
        if !self.ver_mem(w, x) {
            return None;
        }

        self.s /= x;
        // w is a_t without x, so need to recompute
        self.a_t = w.clone();

        Some(())
    }

    fn create_all_mem_wit(&self, s: &[BigUint]) -> Vec<BigUint> {
        root_factor(&self.g, &s, &self.n)
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
                acc.del(x).unwrap();
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

    #[test]
    fn test_batch() {
        let mut rng = thread_rng();

        for _ in 0..10 {
            let lambda = 256; // insecure, but faster tests
            let mut acc = RsaAccumulator::setup(lambda);

            // regular add
            let x0 = rng.gen_prime(lambda);
            acc.add(&x0);

            // batch add
            let a_t = acc.state().clone();
            let xs = (0..4).map(|_| rng.gen_prime(lambda)).collect::<Vec<_>>();
            let w = acc.batch_add(&xs);

            // verify batch add
            assert!(acc.ver_batch_add(&w, &a_t, &xs), "ver_batch_add failed");

            // delete with member
            let x = &xs[2];
            let w = acc.mem_wit_create(x);
            assert!(acc.ver_mem(&w, x), "failed to verify valid witness");

            acc.del_w_mem(&w, x).unwrap();
            assert!(
                !acc.ver_mem(&w, x),
                "witness verified, even though it was deleted"
            );

            // create all members witness
            // current state contains xs\x + x0
            let s = vec![x0.clone(), xs[0].clone(), xs[1].clone(), xs[3].clone()];
            let ws = acc.create_all_mem_wit(&s);

            for (w, x) in ws.iter().zip(s.iter()) {
                assert!(acc.ver_mem(w, x));
            }

            // batch delete
            let a_t = acc.state().clone();
            let pairs = s
                .iter()
                .cloned()
                .zip(ws.iter().cloned())
                .take(3)
                .collect::<Vec<_>>();
            let w = acc.batch_del(&pairs[..]).unwrap();

            assert!(acc.ver_batch_del(&w, &a_t, &s[..3]), "ver_batch_del failed");
        }
    }
}
