use bellman::{ConstraintSystem, SynthesisError};
use pairing::{Engine, Field};

/// Circuit version of sloth decoding.
pub fn decode<E, CS>(
    mut cs: CS,
    key: &E::Fr,
    ciphertext: &E::Fr,
    rounds: usize,
) -> Result<E::Fr, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let mut plaintext = *ciphertext;

    for i in 0..rounds {
        let cs = &mut cs.namespace(|| format!("round {}", i));

        // c
        let mut tmp_value = plaintext;
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
        tmp_value.mul_assign(&plaintext);
        tmp_value.sub_assign(key);
        let output = cs.alloc(|| "output", || Ok(tmp_value))?;
        cs.enforce(
            || "c5 = (c4)*c - k",
            |lc| lc + c4,
            |lc| lc + c,
            |lc| lc + output + (*key, CS::one()),
        );
        plaintext = tmp_value;
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::test::TestConstraintSystem;
    use crypto::sloth;
    use pairing::bls12_381::{Bls12, Fr};
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn sloth_snark_decode() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..10 {
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();
            let ciphertext = sloth::encode_element::<Bls12>(&key, &plaintext, 10);

            // Vanilla
            let decrypted = sloth::decode_element::<Bls12>(&key, &ciphertext, 10);
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let out = decode(cs.namespace(|| "sloth"), &key, &ciphertext, 10).unwrap();

            assert!(cs.is_satisfied());
            assert_eq!(out, decrypted);
        }
    }

    #[test]
    fn sloth_snark_decode_bad() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..10 {
            let key: Fr = rng.gen();
            let key_bad: Fr = rng.gen();
            let plaintext: Fr = rng.gen();

            let ciphertext = sloth::encode_element::<Bls12>(&key, &plaintext, 10);

            let decrypted = sloth::decode_element::<Bls12>(&key, &ciphertext, 10);
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let out = decode(cs.namespace(|| "sloth"), &key_bad, &ciphertext, 10).unwrap();

            assert!(cs.is_satisfied());
            assert_ne!(out, decrypted);
        }
    }

    #[test]
    fn sloth_snark_decode_different_iterations() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..10 {
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();

            let ciphertext = sloth::encode_element::<Bls12>(&key, &plaintext, 10);

            let decrypted = sloth::decode_element::<Bls12>(&key, &ciphertext, 10);

            let mut cs = TestConstraintSystem::<Bls12>::new();
            let out9 = decode(cs.namespace(|| "sloth 9"), &key, &ciphertext, 9).unwrap();
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let out10 = decode(cs.namespace(|| "sloth 10"), &key, &ciphertext, 10).unwrap();
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let out11 = decode(cs.namespace(|| "sloth 11"), &key, &ciphertext, 11).unwrap();

            assert!(cs.is_satisfied());
            assert_ne!(out9, decrypted);
            assert_eq!(out10, decrypted);
            assert_ne!(out11, decrypted);
        }
    }
}
