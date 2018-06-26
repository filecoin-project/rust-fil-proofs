use bellman::groth16;
use bellman::Circuit;
use error::Result;
use pairing::bls12_381::Bls12;
use pairing::Engine;
use proof::ProofScheme;
use rand::{SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::JubjubEngine;

pub trait CompoundProof<'a, E: JubjubEngine, S: ProofScheme<'a>, C: Circuit<E>> {
    fn prove<'b>(
        circuit: &'b C,
        pub_params: S::PublicParams,
        pub_in: S::PublicInputs,
        priv_in: S::PrivateInputs,
        params: &'a E::Params,
    ) -> Result<(groth16::Proof<E>, S::Proof, groth16::Parameters<E>)>
    where
        &'b C: Circuit<E>,
    {
        let vanilla_proof = S::prove(&pub_params, &pub_in, &priv_in)?;

        let (circuit_proof, groth_params) =
            Self::circuit_proof(circuit, pub_in, &vanilla_proof, params)?;

        Ok((circuit_proof, vanilla_proof, groth_params))
    }

    fn circuit_proof<'b>(
        circuit: &'b C,
        pub_in: S::PublicInputs,
        vanilla_proof: &S::Proof,
        params: &'a E::Params,
    ) -> Result<(groth16::Proof<E>, groth16::Parameters<E>)>
    where
        &'b C: Circuit<E>,
    {
        // TODO: better random numbers
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let groth_params = groth16::generate_random_parameters::<E, _, _>(circuit, rng)?;

        // TODO: don't do this, we should store the circuit
        let gp = {
            let vp = vanilla_proof;
            let circuit = Self::make_circuit(&pub_in, &vp, params);

            // TODO: don't do this, we should store the circuit
            let groth_proof = groth16::create_random_proof(circuit, &groth_params, rng)?;
            let mut proof_vec = vec![];
            groth_proof.write(&mut proof_vec)?;
            groth16::Proof::<E>::read(&proof_vec[..])?
        };

        Ok((gp, groth_params))
    }

    fn verify(
        groth_params: groth16::Parameters<E>,
        vanilla_proof: &S::Proof,
        proof: groth16::Proof<E>,
        public_inputs: &S::PublicInputs,
    ) -> Result<bool> {
        let pvk = groth16::prepare_verifying_key(&groth_params.vk);
        let inputs = Self::inputize(public_inputs, vanilla_proof);

        Ok(groth16::verify_proof(&pvk, &proof, inputs.as_slice())?)
    }

    fn inputize(pub_in: &S::PublicInputs, vanilla_proof: &S::Proof) -> Vec<E::Fr>;

    fn make_circuit(
        public_inputs: &S::PublicInputs,
        vanilla_proof: &S::Proof,
        params: &'a E::Params,
    ) -> C;
}
