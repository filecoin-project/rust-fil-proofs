use bellman::{ConstraintSystem, SynthesisError};
use pairing::Field;
use sapling_crypto::jubjub::JubjubEngine;

pub fn sloth_dec<E, CS>(
    cs: &mut CS,
    k_value: E::Fr,
    c_value: E::Fr,
) -> Result<E::Fr, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    // Compute (c)^5-k mod p.

    let mut tmp_value = c_value;
    let mut c = cs.alloc(|| "c", || Ok(tmp_value))?;

    tmp_value.square();
    let mut c2 = cs.alloc(|| "c2", || Ok(tmp_value))?;
    cs.enforce(|| "c2 = (c)^2", |lc| lc + c, |lc| lc + c, |lc| lc + c2);

    tmp_value.square();
    let mut tmp_c4 = tmp_value.clone();

    let mut c4 = cs.alloc(|| "c4", || Ok(tmp_value))?;
    cs.enforce(|| "c4 = (c2)^2", |lc| lc + c2, |lc| lc + c2, |lc| lc + c4);

    //    1  c c2 c4 out
    // [  0  0  0  1  0 ] // a
    // [  0  1  0  0  0 ] // b
    // [  0  0  0  0  1 ] // c

    tmp_value.mul_assign(&c_value);
    tmp_value.sub_assign(&k_value);

    let mut output = cs.alloc(|| "output", || Ok(tmp_value))?;

    let mut k_cs = k_value;
    let c4_inv = tmp_c4.inverse().unwrap();
    k_cs.mul_assign(&c4_inv);

    // (c4)*(c- k_cs*1) = [c4*c - c4*k_cs] = [c^5 - c4 * (k/c4)] = c^5-k
    cs.enforce(
        || "c5 = (c4)*c - k",
        |lc| lc + c4,
        |lc| lc + c - (k_cs, CS::one()),
        |lc| lc + output,
    );

    Ok(tmp_value)
}

#[cfg(test)]
mod tests {
    use super::sloth_dec;
    use circuit::test::TestConstraintSystem;
    use crypto::sloth::BlsSloth;
    use pairing::bls12_381::Bls12;
    use pairing::bls12_381::Fr;
    use pairing::PrimeField;
    // use sapling_crypto::jubjub::JubjubEngine;
    // use bellman::ConstraintSystem;

    #[test]
    fn test_snark_sloth_dec() {
        let key = Fr::from_str("11111111").unwrap();
        let plaintext = Fr::from_str("123456789").unwrap();
        let ciphertext = BlsSloth::enc(&key, &plaintext);

        // Vanilla
        let decrypted = BlsSloth::dec(&key, &ciphertext);
        let mut cs = TestConstraintSystem::<Bls12>::new();
        let out = sloth_dec(&mut cs, key, ciphertext).unwrap();

        assert!(cs.is_satisfied());
        assert_eq!(out, decrypted);
    }
}
