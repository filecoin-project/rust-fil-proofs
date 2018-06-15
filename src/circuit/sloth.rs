use bellman::{ConstraintSystem, SynthesisError};
use pairing::{Engine, Field};

/// Circuit version of sloth decoding.
pub fn decode<E, CS>(cs: &mut CS, k_value: E::Fr, c_value: E::Fr) -> Result<E::Fr, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    // Compute (c)^5-k mod p.

    // c
    let mut tmp_value = c_value;
    let c = cs.alloc(|| "c", || Ok(tmp_value))?;

    // c^2
    //    1  c c2 c4 out
    // [  0  1  0  0  0 ] // a
    // [  0  1  0  0  0 ] // b
    // [  0  0  1  0  0 ] // c
    // c1 * c1 = c2
    tmp_value.square();
    let c2 = cs.alloc(|| "c2", || Ok(tmp_value))?;
    cs.enforce(|| "c2 = (c)^2", |lc| lc + c, |lc| lc + c, |lc| lc + c2);

    // c^4
    //    1  c c2 c4 out
    // [  0  0  1  0  0 ] // a
    // [  0  0  1  0  0 ] // b
    // [  0  0  0  1  0 ] // c
    // c2 * c2 = c4
    tmp_value.square();
    let c4 = cs.alloc(|| "c4", || Ok(tmp_value))?;
    cs.enforce(|| "c4 = (c2)^2", |lc| lc + c2, |lc| lc + c2, |lc| lc + c4);

    // c^4*c - k
    //    1  c c2 c4 out
    // [  0  0  0  1  0 ] // a
    // [  0  1  0  0  0 ] // b
    // [  k  0  0  0  1 ] // c
    // (c4)*(c) = out + k => c^4*c-k = out
    tmp_value.mul_assign(&c_value);
    tmp_value.sub_assign(&k_value);
    let output = cs.alloc(|| "output", || Ok(tmp_value))?;
    cs.enforce(
        || "c5 = (c4)*c - k",
        |lc| lc + c4,
        |lc| lc + c,
        |lc| lc + output + (k_value, CS::one()),
    );

    Ok(tmp_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::TestConstraintSystem;
    use crypto::sloth;
    use pairing::bls12_381::{Bls12, Fr};
    use pairing::PrimeField;

    #[test]
    fn test_snark_sloth_dec() {
        let key = Fr::from_str("11111111").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = sloth::encode::<Bls12>(&key, &plaintext);

        // Vanilla
        let decrypted = sloth::decode::<Bls12>(&key, &ciphertext);
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let out = decode(&mut cs, key, ciphertext).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(out, decrypted);
    }
    #[test]
    fn test_snark_sloth_dec_bad() {
        let key = Fr::from_str("11111111").unwrap();
        let key_bad = Fr::from_str("11111112").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = sloth::encode::<Bls12>(&key, &plaintext);

        // Vanilla
        let decrypted = sloth::decode::<Bls12>(&key, &ciphertext);
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let out = decode(&mut cs, key_bad, ciphertext).unwrap();

        assert!(cs.is_satisfied());
        assert_ne!(out, decrypted);
    }
}
