use bellman::{ConstraintSystem, SynthesisError};
use pairing::{Engine, Field};
use sapling_crypto::circuit::num;

use crate::circuit::constraint;

/// Circuit version of sloth decoding.
pub fn decode<E, CS>(
    mut cs: CS,
    key: &num::AllocatedNum<E>,
    ciphertext: Option<E::Fr>,
    rounds: usize,
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let mut plaintext = num::AllocatedNum::alloc(cs.namespace(|| "decoded"), || {
        Ok(ciphertext.ok_or_else(|| SynthesisError::AssignmentMissing)?)
    })?;

    for i in 0..rounds {
        let cs = &mut cs.namespace(|| format!("round {}", i));

        let c = plaintext;
        let c2 = c.square(cs.namespace(|| "c^2"))?;
        let c4 = c2.square(cs.namespace(|| "c^4"))?;
        let c5 = c4.mul(cs.namespace(|| "c^5"), &c)?;

        plaintext = sub(cs.namespace(|| "c^5 - k"), &c5, key)?;
    }

    if rounds == 0 {
        plaintext = sub(cs.namespace(|| "plaintext - k"), &plaintext, key)?;
    }

    Ok(plaintext)
}

fn sub<E: Engine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    a: &num::AllocatedNum<E>,
    b: &num::AllocatedNum<E>,
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    let res = num::AllocatedNum::alloc(cs.namespace(|| "sub num"), || {
        let mut tmp = a
            .get_value()
            .ok_or_else(|| SynthesisError::AssignmentMissing)?;
        tmp.sub_assign(
            &b.get_value()
                .ok_or_else(|| SynthesisError::AssignmentMissing)?,
        );

        Ok(tmp)
    })?;

    // a - b = res
    constraint::difference(&mut cs, || "subtraction constraint", &a, &b, &res);

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto::sloth;
    use pairing::bls12_381::{Bls12, Fr};
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn sloth_snark_decode() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..10 {
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();
            let ciphertext = sloth::encode::<Bls12>(&key, &plaintext, 10);

            // Vanilla
            let decrypted = sloth::decode::<Bls12>(&key, &ciphertext, 10);

            assert_eq!(plaintext, decrypted, "vanilla failed");

            let mut cs = TestConstraintSystem::<Bls12>::new();

            let key_num = num::AllocatedNum::alloc(cs.namespace(|| "key"), || Ok(key)).unwrap();
            let out = decode(cs.namespace(|| "sloth"), &key_num, Some(ciphertext), 10).unwrap();

            assert!(cs.is_satisfied());
            assert_eq!(out.get_value().unwrap(), decrypted, "no interop");
        }
    }

    #[test]
    fn sloth_snark_decode_bad() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..10 {
            let key: Fr = rng.gen();
            let key_bad: Fr = rng.gen();
            let plaintext: Fr = rng.gen();

            let ciphertext = sloth::encode::<Bls12>(&key, &plaintext, 10);

            let decrypted = sloth::decode::<Bls12>(&key, &ciphertext, 10);
            let mut cs = TestConstraintSystem::<Bls12>::new();
            let key_bad_num =
                num::AllocatedNum::alloc(cs.namespace(|| "key bad"), || Ok(key_bad)).unwrap();

            let out = decode(cs.namespace(|| "sloth"), &key_bad_num, Some(ciphertext), 10).unwrap();

            assert!(cs.is_satisfied());
            assert_ne!(out.get_value().unwrap(), decrypted);
        }
    }

    #[test]
    fn sloth_snark_decode_different_iterations() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..10 {
            let key: Fr = rng.gen();
            let plaintext: Fr = rng.gen();

            let ciphertext = sloth::encode::<Bls12>(&key, &plaintext, 10);
            let decrypted = sloth::decode::<Bls12>(&key, &ciphertext, 10);

            {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let key_num = num::AllocatedNum::alloc(cs.namespace(|| "key"), || Ok(key)).unwrap();

                let out9 =
                    decode(cs.namespace(|| "sloth 9"), &key_num, Some(ciphertext), 9).unwrap();

                assert!(cs.is_satisfied());
                assert_ne!(out9.get_value().unwrap(), decrypted);
            }

            {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let key_num = num::AllocatedNum::alloc(cs.namespace(|| "key"), || Ok(key)).unwrap();
                let out10 =
                    decode(cs.namespace(|| "sloth 10"), &key_num, Some(ciphertext), 10).unwrap();

                assert!(cs.is_satisfied());
                assert_eq!(out10.get_value().unwrap(), decrypted);
            }

            {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let key_num = num::AllocatedNum::alloc(cs.namespace(|| "key"), || Ok(key)).unwrap();
                let out11 =
                    decode(cs.namespace(|| "sloth 11"), &key_num, Some(ciphertext), 11).unwrap();

                assert!(cs.is_satisfied());
                assert_ne!(out11.get_value().unwrap(), decrypted);
            }
        }
    }

    #[test]
    fn sub_constraint() {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        for _ in 0..100 {
            let mut cs = TestConstraintSystem::<Bls12>::new();

            let a = num::AllocatedNum::alloc(cs.namespace(|| "a"), || Ok(rng.gen())).unwrap();
            let b = num::AllocatedNum::alloc(cs.namespace(|| "b"), || Ok(rng.gen())).unwrap();

            let res = sub(cs.namespace(|| "a-b"), &a, &b).unwrap();

            let mut tmp = a.get_value().unwrap().clone();
            tmp.sub_assign(&b.get_value().unwrap());

            assert_eq!(res.get_value().unwrap(), tmp);
            assert!(cs.is_satisfied());
        }
    }
}
