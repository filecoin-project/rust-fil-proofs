use bellman::groth16::*;
use bellman::*;
use pairing::{CurveAffine, CurveProjective, Engine, PrimeField};
use sapling_crypto::jubjub::JubjubEngine;

pub fn verifier<E, CS>(
    mut cs: CS,
    vk: &VerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr],
) -> Result<(), SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    let mut gamma = vk.gamma_g2;
    gamma.negate();
    let mut delta = vk.delta_g2;
    delta.negate();

    let alpha_g1_beta_g2 = E::pairing(vk.alpha_g1, vk.beta_g2);
    let neg_gamma_g2 = gamma.prepare();
    let neg_delta_g2 = delta.prepare();
    let ic = vk.ic.clone();

    // TODO: should this be a constraint?
    assert_eq!(public_inputs.len() + 1, ic.len(), "malformed verifying key");

    let mut acc = ic[0].into_projective();

    for (i, b) in public_inputs.iter().zip(ic.iter().skip(1)) {
        acc.add_assign(&b.mul(i.into_repr()));
    }

    // The original verification equation is:
    // A * B = alpha * beta + inputs * gamma + C * delta
    // ... however, we rearrange it so that it is:
    // A * B - inputs * gamma - C * delta = alpha * beta
    // or equivalently:
    // A * B + inputs * (-gamma) + C * (-delta) = alpha * beta
    // which allows us to do a single final exponentiation.

    let left_hand = E::final_exponentiation(&E::miller_loop(
        [
            (&proof.a.prepare(), &proof.b.prepare()),
            (&acc.into_affine().prepare(), &neg_gamma_g2),
            (&proof.c.prepare(), &neg_delta_g2),
        ]
            .into_iter(),
    )).unwrap();

    let valid = left_hand == alpha_g1_beta_g2;

    if !valid {
        panic!("invalid");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use bellman::ConstraintSystem;
    use circuit::test::TestConstraintSystem;
    use pairing::bls12_381::Bls12;
    use pairing::Field;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::num;

    struct DummyCircuit<E: Engine> {
        arg: Option<E::Fr>,
    }

    impl<E: Engine> Circuit<E> for DummyCircuit<E> {
        fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
            let val = num::AllocatedNum::alloc(cs.namespace(|| "val"), || {
                self.arg.ok_or(SynthesisError::AssignmentMissing)
            })?;

            val.inputize(cs.namespace(|| "val_input"))?;

            cs.enforce(
                || "1 * 1= 1",
                |lc| lc + CS::one(),
                |lc| lc + CS::one(),
                |lc| lc + val.get_variable(),
            );
            Ok(())
        }
    }

    #[test]
    fn verifier_circuit() {
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let one = <Bls12 as Engine>::Fr::one();
        let params = {
            let c = DummyCircuit::<Bls12> { arg: None };
            generate_random_parameters(c, &mut rng).expect("failed to create random parameters")
        };

        let pvk = prepare_verifying_key(&params.vk);

        let proof = {
            let c = DummyCircuit { arg: Some(one) };
            create_random_proof(c, &params, &mut rng).expect("failed to create proof")
        };

        let public_inputs = vec![one];

        let mut cs = TestConstraintSystem::<Bls12>::new();

        // Check the proof -- outside the circuit
        assert!(
            verify_proof(&pvk, &proof, &public_inputs).expect("failed to verify proof"),
            "failed to verify proof (non-circuit)"
        );

        verifier(
            cs.namespace(|| "verifier"),
            &params.vk,
            &proof,
            &public_inputs,
        ).expect("failed to verify proof (circuit)");

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_constraints(), 0);
    }
}
