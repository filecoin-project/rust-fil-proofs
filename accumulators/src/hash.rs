use blake2::Digest;
use generic_array::ArrayLength;
use num_bigint::BigUint;
use rsa::prime::probably_prime;

/// Hash the given numbers to a prime number.
pub fn hash_prime<O: ArrayLength<u8>, D: Digest<OutputSize = O>>(input: &[u8]) -> BigUint {
    let mut y = BigUint::from_bytes_be(&D::digest(input)[..]);

    // TODO: this primality test might not be good enough
    while !probably_prime(&y, 20) {
        y = BigUint::from_bytes_be(&D::digest(&y.to_bytes_be())[..]);
    }

    y
}

#[cfg(test)]
mod tests {
    use super::*;

    use blake2::Blake2b;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_hash_prime() {
        let mut rng = thread_rng();

        for i in 1..10 {
            let mut val = vec![0u8; i * 32];
            rng.fill(&mut val[..]);

            let h = hash_prime::<_, Blake2b>(&val);
            assert!(probably_prime(&h, 20));
        }
    }
}
