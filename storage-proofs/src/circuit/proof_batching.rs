use algebra::{
    bytes::{FromBytes, ToBytes},
    curves::{sw6::SW6, bls12_377::Bls12_377 as Bls12},
    fields::{bls12_377 as bls12, sw6, PrimeField},
    BitIterator,
    PairingEngine,
};
use dpc::gadgets::verifier::{
    groth16::{Groth16VerifierGadget, PreparedVerifyingKeyGadget, ProofGadget, VerifyingKeyGadget},
    NIZKBatchVerifierGadget
};
use snark::{groth16, Circuit, ConstraintSystem, SynthesisError};
use snark_gadgets::{bits::boolean::Boolean, pairing::bls12_377::PairingGadget as Bls12PairingGadget, utils::AllocGadget};
use crate::circuit::multi_proof::MultiProof;
use snark::groth16::VerifyingKey;

type VerifierGadget = Groth16VerifierGadget<Bls12, SW6, Bls12PairingGadget>;
type ProofGadgetT = ProofGadget<Bls12, SW6, Bls12PairingGadget>;
type VkGadget = VerifyingKeyGadget<Bls12, SW6, Bls12PairingGadget>;

#[derive(Clone)]
pub struct ProofBatching {
    pub verifying_key: VerifyingKey<Bls12>,
    pub public_inputs: Vec<Vec<bls12::Fr>>,
    pub groth_proofs: Vec<groth16::Proof<Bls12>>,
}

impl Circuit<SW6> for ProofBatching {
    fn synthesize<CS: ConstraintSystem<SW6>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let mut multi_input_gadgets = Vec::new();

        for i in 0..self.public_inputs.len() {
            let mut input_gadgets = Vec::new();
            for (j, input) in self.public_inputs[i].iter().enumerate() {
                let mut input_bits = BitIterator::new(input.into_repr()).collect::<Vec<_>>();
                // Input must be in little-endian, but BitIterator outputs in big-endian.
                input_bits.reverse();

                let input_bits =
                    Vec::<Boolean>::alloc_input(cs.ns(|| format!("Alloc input: {} {}", i, j)), || {
                        Ok(input_bits)
                    }).unwrap();

                input_gadgets.push(input_bits);
            }
            multi_input_gadgets.push(input_gadgets);
        }

        let mut proof_gadgets = Vec::new();
        for (i, proof) in self.groth_proofs.iter().enumerate() {
            let proof_gadget = ProofGadgetT::alloc(
                cs.ns(|| format!("Alloc Proof Gadget: {}", i)),
                || Ok(proof)
            ).unwrap();
            proof_gadgets.push(proof_gadget);
        }

        let vk_gadget = VkGadget::alloc_input(
            cs.ns(|| "Vk"), || Ok(&self.verifying_key)).unwrap();

        let mut inputs_batch_iter: Vec<_> =
            multi_input_gadgets.iter().map(|x| x.iter()).collect();

        <VerifierGadget as NIZKBatchVerifierGadget<SW6>>::check_batch_verify(cs.ns(|| "Verify Proofs"),
                                                                             &vk_gadget,
                                                                             &mut inputs_batch_iter,
                                                                             &proof_gadgets,
        ).unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use std::borrow::Borrow;
    use crate::circuit::test::TestConstraintSystem;
    use algebra::utils::ToEngineFr;

    struct DummyCircuit<E: PairingEngine> {
        inputs:          Vec<Option<E::Fr>>,
        num_constraints: usize,
    }

    impl<E: PairingEngine> Circuit<E> for DummyCircuit<E> {
        fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
            assert!(self.inputs.len() >= 2);
            assert!(self.num_constraints >= self.inputs.len());

            let mut variables: Vec<_> = Vec::with_capacity(self.inputs.len());
            for (i, input) in self.inputs.into_iter().enumerate() {
                let input_var = cs.alloc_input(
                    || format!("Input {}", i),
                    || input.ok_or(SynthesisError::AssignmentMissing),
                )?;
                variables.push((input, input_var));
            }

            for i in 0..self.num_constraints {
                let new_entry = {
                    let (input_1_val, input_1_var) = variables[i];
                    let (input_2_val, input_2_var) = variables[i + 1];
                    let result_val = input_1_val
                        .and_then(|input_1| input_2_val.map(|input_2| input_1 * &input_2));
                    let result_var = cs.alloc(
                        || format!("Result {}", i),
                        || result_val.ok_or(SynthesisError::AssignmentMissing),
                    )?;
                    cs.enforce(
                        || format!("Enforce constraint {}", i),
                        |lc| lc + input_1_var,
                        |lc| lc + input_2_var,
                        |lc| lc + result_var,
                    );
                    (result_val, result_var)
                };
                variables.push(new_entry);
            }
            Ok(())
        }
    }
    #[test]
    fn test_proof_batching_circuit() {
        let num_inputs = 4;
        let num_constraints = num_inputs;
        let rng = &mut thread_rng();

        let params = {
            let c = DummyCircuit::<Bls12> {
                inputs:          vec![None; num_inputs],
                num_constraints: num_inputs,
            };

            groth16::generate_random_parameters(c, rng).unwrap()
        };

        let mut test_proofs  = Vec::new();

        for _ in 0..2 {
            let mut inputs: Vec<Option<bls12::Fr>> = Vec::with_capacity(num_inputs);
            for _ in 0..num_inputs {
                inputs.push(Some(rng.gen()));
            }

            let proof = {
                let c = DummyCircuit {
                    inputs:          inputs.clone(),
                    num_constraints: num_inputs,
                };
                // Create a groth16 proof with our parameters.
                groth16::create_random_proof(c, &params, rng).unwrap()
            };

            // Map options to successful values
            let inputs: Vec<_> = inputs.into_iter().flatten().collect();

            test_proofs.push((inputs, proof));
        }

        // TODO: Get rid of cloning
        let proof_batching_circuit = ProofBatching {
            verifying_key: params.vk,
            public_inputs: test_proofs.clone().into_iter().map(|tp| tp.0).collect(),
            groth_proofs: test_proofs.clone().into_iter().map(|tp| tp.1).collect(),
        };

//        {
//            let mut cs = TestConstraintSystem::new();
//
//            proof_batching_circuit.synthesize(&mut cs).expect("failed to synthesize");
//
//            if !cs.is_satisfied() {
//                panic!(
//                    "failed to satisfy: {:?}",
//                    cs.which_is_unsatisfied().unwrap()
//                );
//            }
//        }

        let batch_params = groth16::generate_random_parameters(proof_batching_circuit.clone(), rng).unwrap();
        let batch_proof = groth16::create_random_proof(proof_batching_circuit.clone(), &batch_params, rng).unwrap();
        let verified = groth16::verify_proof(
            &batch_params.vk.into(),
            &batch_proof,
            &proof_batching_circuit
                .public_inputs
                .into_iter()
                .map(|pi|
                    pi.iter().map(|v| sw6::Fr::from_repr(v.into_repr())).collect()
                )
                .collect::<Vec<_>>()
        ).unwrap();
    }
}
