use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use ff::Field;
use paired::Engine;

use crate::crypto::mimc::MIMC_ROUNDS;

pub struct MiMC<'a, E: Engine> {
    pub xl: Option<E::Fr>,
    pub xr: Option<E::Fr>,
    pub constants: &'a [E::Fr],
}

impl<'a, E: Engine> Circuit<E> for MiMC<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        assert_eq!(self.constants.len(), MIMC_ROUNDS);

        // Allocate the first component of the preimage.
        let mut xl_value = self.xl;
        let mut xl = cs.alloc(
            || "preimage xl",
            || xl_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // Allocate the second component of the preimage.
        let mut xr_value = self.xr;
        let mut xr = cs.alloc(
            || "preimage xr",
            || xr_value.ok_or(SynthesisError::AssignmentMissing),
        )?;

        for i in 0..MIMC_ROUNDS {
            // xL, xR := xR + (xL + Ci)^3, xL
            let cs = &mut cs.namespace(|| format!("round {}", i));

            // tmp = (xL + Ci)^2
            let tmp_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.square();
                e
            });
            let tmp = cs.alloc(
                || "tmp",
                || tmp_value.ok_or(SynthesisError::AssignmentMissing),
            )?;

            cs.enforce(
                || "tmp = (xL + Ci)^2",
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + tmp,
            );

            // new_xL = xR + (xL + Ci)^3
            // new_xL = xR + tmp * (xL + Ci)
            // new_xL - xR = tmp * (xL + Ci)
            let new_xl_value = xl_value.map(|mut e| {
                e.add_assign(&self.constants[i]);
                e.mul_assign(&tmp_value.unwrap());
                e.add_assign(&xr_value.unwrap());
                e
            });

            let new_xl = if i == (MIMC_ROUNDS - 1) {
                // This is the last round, xL is our image and so
                // we allocate a public input.
                cs.alloc_input(
                    || "image",
                    || new_xl_value.ok_or(SynthesisError::AssignmentMissing),
                )?
            } else {
                cs.alloc(
                    || "new_xl",
                    || new_xl_value.ok_or(SynthesisError::AssignmentMissing),
                )?
            };

            cs.enforce(
                || "new_xL = xR + (xL + Ci)^3",
                |lc| lc + tmp,
                |lc| lc + xl + (self.constants[i], CS::one()),
                |lc| lc + new_xl - xr,
            );

            // xR = xL
            xr = xl;
            xr_value = xl_value;

            // xL = new_xL
            xl = new_xl;
            xl_value = new_xl_value;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use paired::bls12_381::Bls12;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_mimc() {
        let rng = &mut thread_rng();
        let constants = (0..MIMC_ROUNDS).map(|_| rng.gen()).collect::<Vec<_>>();

        let params = {
            let c = MiMC::<Bls12> {
                xl: None,
                xr: None,
                constants: &constants,
            };

            generate_random_parameters(c, rng).unwrap()
        };

        // Prepare the verification key (for proof verification)
        let pvk = prepare_verifying_key(&params.vk);

        let xl = rng.gen();
        let xr = rng.gen();
        let image = crate::crypto::mimc::mimc::<Bls12>(xl, xr, &constants);

        let c = MiMC {
            xl: Some(xl),
            xr: Some(xr),
            constants: &constants,
        };

        let proof = create_random_proof(c, &params, rng).unwrap();
        assert!(verify_proof(&pvk, &proof, &[image]).unwrap());
    }
}
