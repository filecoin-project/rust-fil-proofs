use bellman::{groth16, Circuit};
use error::Result;
use proof::ProofScheme;
use rand::{SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::JubjubEngine;

pub struct SetupParams<'a, 'b: 'a, E: JubjubEngine, S: ProofScheme<'a>>
where
    <S as ProofScheme<'a>>::SetupParams: 'b,
{
    pub vanilla_params: &'b <S as ProofScheme<'a>>::SetupParams,
    // TODO: would be nice to use a reference, but that requires E::Params to impl Clone or Copy I think
    pub engine_params: &'a E::Params,
}

pub struct PublicParams<'a, E: JubjubEngine, S: ProofScheme<'a>> {
    pub vanilla_params: S::PublicParams,
    pub engine_params: &'a E::Params,
}

pub struct Proof<E: JubjubEngine> {
    pub circuit_proof: groth16::Proof<E>,
    pub groth_params: groth16::Parameters<E>,
}

/// The CompoundProof trait bundles a proof::ProofScheme and a bellman::Circuit together.
/// It provides methods equivalent to those provided by proof::ProofScheme (setup, prove, verify).
/// See documentation at proof::ProofScheme for details.
/// Implementations should generally only need to supply circuit and generate_public_inputs.
/// The remaining trait methods are used internally and implement the necessary plumbing.
pub trait CompoundProof<'a, E: JubjubEngine, S: ProofScheme<'a>, C: Circuit<E>> {
    // setup is equivalent to ProofScheme::setup.
    fn setup<'b>(sp: &SetupParams<'a, 'b, E, S>) -> Result<PublicParams<'a, E, S>> {
        Ok(PublicParams {
            vanilla_params: S::setup(sp.vanilla_params)?,
            engine_params: sp.engine_params,
        })
    }

    /// prove is equivalent to ProofScheme::prove.
    fn prove(
        pub_params: &PublicParams<'a, E, S>,
        pub_in: &S::PublicInputs,
        priv_in: &S::PrivateInputs,
    ) -> Result<Proof<E>> {
        let vanilla_proof = S::prove(&pub_params.vanilla_params, pub_in, priv_in)?;

        let (groth_proof, groth_params) = Self::circuit_proof(
            pub_in,
            &vanilla_proof,
            &pub_params.vanilla_params,
            pub_params.engine_params,
        )?;

        Ok(Proof {
            circuit_proof: groth_proof,
            groth_params,
        })
    }

    // verify is equivalent to ProofScheme::verify.
    fn verify(
        public_params: &S::PublicParams,
        public_inputs: &S::PublicInputs,
        proof: Proof<E>,
    ) -> Result<bool> {
        let pvk = groth16::prepare_verifying_key(&proof.groth_params.vk);
        let inputs = Self::generate_public_inputs(public_inputs, public_params);

        Ok(groth16::verify_proof(
            &pvk,
            &proof.circuit_proof,
            inputs.as_slice(),
        )?)
    }

    /// circuit_proof creates and synthesizes a circuit from concrete params/inputs, then generates a
    /// groth proof from it. It returns a tuple of the groth proof and params.
    /// circuit_proof is used internally and should neither be called nor implemented outside of
    /// default trait methods.
    fn circuit_proof<'b>(
        pub_in: &S::PublicInputs,
        vanilla_proof: &S::Proof,
        pub_params: &'b S::PublicParams,
        params: &'a E::Params,
    ) -> Result<(groth16::Proof<E>, groth16::Parameters<E>)> {
        // TODO: better random numbers
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // TODO: Don't actually generate groth parameters here, certainly not random ones.
        // The parameters will need to have been generated in advance and will be constants
        // associated with a given top-level circuit.
        // They should probably be moved to PublicParams.
        // For now, this is most expedient, since we need the public/private inputs
        // in order to generate a circuit at all.
        let circuit = Self::circuit(&pub_in, &vanilla_proof, &pub_params, params);
        let groth_params = groth16::generate_random_parameters::<E, _, _>(circuit, rng)?;

        let circuit = Self::circuit(&pub_in, &vanilla_proof, &pub_params, params);
        let groth_proof = groth16::create_random_proof(circuit, &groth_params, rng)?;

        let mut proof_vec = vec![];
        groth_proof.write(&mut proof_vec)?;
        let gp = groth16::Proof::<E>::read(&proof_vec[..])?;

        Ok((gp, groth_params))
    }

    /// generate_public_inputs generates public inputs suitable for use as input during verification
    /// of a proof generated from this CompoundProof's bellman::Circuit (C). These inputs correspond
    /// to those allocated when C is synthesized.
    fn generate_public_inputs(pub_in: &S::PublicInputs, pub_params: &S::PublicParams)
        -> Vec<E::Fr>;

    /// circuit constructs an instance of this CompoundProof's bellman::Circuit.
    /// circuit takes PublicInputs, PublicParams, and Proof from this CompoundProof's proof::ProofScheme (S)
    /// and uses them to initialize Circuit fields which will be used to construct public and private
    /// inputs during circuit synthesis.
    fn circuit(
        public_inputs: &S::PublicInputs,
        vanilla_proof: &S::Proof,
        public_param: &S::PublicParams,
        engine_params: &'a E::Params,
    ) -> C;
}
