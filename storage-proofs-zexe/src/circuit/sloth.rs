use std::ops::SubAssign;

use algebra::curves::bls12_381::Bls12_381 as Bls12;
use algebra::fields::bls12_381::Fr;
use snark::{ConstraintSystem, SynthesisError};
use snark_gadgets::fields::{fp::FpGadget, FieldGadget};
use snark_gadgets::utils::AllocGadget;

use crate::circuit::constraint;

/// Circuit version of sloth decoding.
pub fn decode<CS>(
    mut cs: CS,
    key: &FpGadget<Bls12>,
    ciphertext: Option<Fr>,
    rounds: usize,
) -> Result<FpGadget<Bls12>, SynthesisError>
where
    CS: ConstraintSystem<Bls12>,
{
    let mut plaintext = FpGadget::alloc(cs.ns(|| "decoded"), || {
        Ok(ciphertext.ok_or_else(|| SynthesisError::AssignmentMissing)?)
    })?;

    for i in 0..rounds {
        let cs = &mut cs.ns(|| format!("round {}", i));

        let c = plaintext;
        let c2 = c.square(cs.ns(|| "c^2"))?;
        let c4 = c2.square(cs.ns(|| "c^4"))?;
        let c5 = c4.mul(cs.ns(|| "c^5"), &c)?;

        plaintext = sub(cs.ns(|| "c^5 - k"), &c5, key)?;
    }

    if rounds == 0 {
        plaintext = sub(cs.ns(|| "plaintext - k"), &plaintext, key)?;
    }

    Ok(plaintext)
}

fn sub<CS: ConstraintSystem<Bls12>>(
    mut cs: CS,
    a: &FpGadget<Bls12>,
    b: &FpGadget<Bls12>,
) -> Result<FpGadget<Bls12>, SynthesisError> {
    let res = FpGadget::alloc(cs.ns(|| "sub num"), || {
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
    constraint::difference(&mut cs, || "subtraction constraint", &a, &b, &res)?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::test::TestConstraintSystem;
    use crate::crypto::sloth;
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

            let key_num = FpGadget::alloc(cs.ns(|| "key"), || Ok(key)).unwrap();
            let out = decode(cs.ns(|| "sloth"), &key_num, Some(ciphertext), 10).unwrap();

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
            let key_bad_num = FpGadget::alloc(cs.ns(|| "key bad"), || Ok(key_bad)).unwrap();

            let out = decode(cs.ns(|| "sloth"), &key_bad_num, Some(ciphertext), 10).unwrap();

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
                let key_num = FpGadget::alloc(cs.ns(|| "key"), || Ok(key)).unwrap();

                let out9 = decode(cs.ns(|| "sloth 9"), &key_num, Some(ciphertext), 9).unwrap();

                assert!(cs.is_satisfied());
                assert_ne!(out9.get_value().unwrap(), decrypted);
            }

            {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let key_num = FpGadget::alloc(cs.ns(|| "key"), || Ok(key)).unwrap();
                let out10 = decode(cs.ns(|| "sloth 10"), &key_num, Some(ciphertext), 10).unwrap();

                assert!(cs.is_satisfied());
                assert_eq!(out10.get_value().unwrap(), decrypted);
            }

            {
                let mut cs = TestConstraintSystem::<Bls12>::new();
                let key_num = FpGadget::alloc(cs.ns(|| "key"), || Ok(key)).unwrap();
                let out11 = decode(cs.ns(|| "sloth 11"), &key_num, Some(ciphertext), 11).unwrap();

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

            let a_val: Fr = rng.gen();
            let b_val: Fr = rng.gen();

            let a = FpGadget::alloc(cs.ns(|| "a"), || Ok(a_val)).unwrap();
            let b = FpGadget::alloc(cs.ns(|| "b"), || Ok(b_val)).unwrap();

            let res = sub(cs.ns(|| "a-b"), &a, &b).expect("subtraction failed");

            let mut tmp = a.get_value().unwrap().clone();
            tmp.sub_assign(&b.get_value().unwrap());

            assert_eq!(res.get_value().unwrap(), tmp);
            assert!(cs.is_satisfied());
        }
    }
}
