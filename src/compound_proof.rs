use bellman::groth16;
use bellman::Circuit;
use error::Result;
use proof::ProofScheme;
use rand::{SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::JubjubEngine;

pub struct SetupParams<'a, E: JubjubEngine, S: ProofScheme<'a>>
where
    <S as ProofScheme<'a>>::SetupParams: 'a,
{
    vanilla_params: &'a <S as ProofScheme<'a>>::SetupParams,
    engine_params: &'a E::Params,
}

pub struct PublicParams<'a, E: JubjubEngine, S: ProofScheme<'a>> {
    vanilla_params: S::PublicParams,
    engine_params: E::Params,
}

pub struct Proof<'a, E: JubjubEngine, S: ProofScheme<'a>> {
    circuit_proof: groth16::Proof<E>,
    vanilla_proof: S::Proof,
    engine_params: groth16::Parameters<E>,
}

pub trait CompoundProof<'a, 'c, E: JubjubEngine, S: ProofScheme<'a>, C: Circuit<E>> {
    fn setup(sp: SetupParams<E, S>) -> Result<PublicParams<E, S>> {
        Ok(PublicParams {
            vanilla_params: &S::setup(sp.vanilla_params)?.clone(),
            engine_params: &sp.engine_params.clone(),
        })
    }

    fn prove<'b>(
        pub_params: PublicParams<'a, E, S>,
        pub_in: S::PublicInputs,
        priv_in: S::PrivateInputs,
    ) -> Result<Proof<'a, E, S>> {
        let vanilla_proof = S::prove(&pub_params, &pub_in, &priv_in)?;

        let (groth_proof, groth_params) =
            Self::circuit_proof(pub_in, &vanilla_proof, pub_params.engine_params)?;

        Ok(Proof {
            circuit_proof: groth_proof,
            vanilla_proof: vanilla_proof,
            engine_params: groth_params,
        })
    }

    fn verify(public_inputs: &S::PublicInputs, proof: Proof<'a, E, S>) -> Result<bool> {
        let pvk = groth16::prepare_verifying_key(&proof.engine_params.vk);
        let inputs = Self::inputize(public_inputs, &proof.vanilla_proof);

        Ok(groth16::verify_proof(
            &pvk,
            &proof.circuit_proof,
            inputs.as_slice(),
        )?)
    }

    fn circuit_proof<'b>(
        pub_in: S::PublicInputs,
        vanilla_proof: &S::Proof,
        params: &'a E::Params,
    ) -> Result<(groth16::Proof<E>, groth16::Parameters<E>)> {
        // TODO: better random numbers
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // TODO: don't do this, we should store the circuit
        let vp = vanilla_proof;
        let circuit = Self::make_circuit(&pub_in, &vp, params);

        let groth_params = groth16::generate_random_parameters::<E, _, _>(circuit, rng)?;

        // FIXME: Don't do this -- either Circuit must implement Copy,
        // or generate_random_parameters/generate_parameters must borrow circuit.
        let circuit = Self::make_circuit(&pub_in, &vp, params);

        let groth_proof = groth16::create_random_proof(circuit, &groth_params, rng)?;
        let mut proof_vec = vec![];
        groth_proof.write(&mut proof_vec)?;
        let gp = groth16::Proof::<E>::read(&proof_vec[..])?;

        Ok((gp, groth_params))
    }

    fn inputize(pub_in: &S::PublicInputs, vanilla_proof: &S::Proof) -> Vec<E::Fr>;

    fn make_circuit(
        public_inputs: &S::PublicInputs,
        vanilla_proof: &S::Proof,
        params: &'a E::Params,
    ) -> C;
}
