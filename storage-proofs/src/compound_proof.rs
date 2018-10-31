use bellman::{groth16, Circuit};
use circuit::multi_proof::MultiProof;
use error::Result;
use parameter_cache::{CacheableParameters, ParameterSetIdentifier};
use partitions;
use proof::ProofScheme;
use rand::{SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::JubjubEngine;

pub struct SetupParams<'a, 'b: 'a, E: JubjubEngine, S: ProofScheme<'a>>
where
    <S as ProofScheme<'a>>::SetupParams: 'b,
{
    pub vanilla_params: &'b <S as ProofScheme<'a>>::SetupParams,
    pub engine_params: &'a E::Params,
    pub partitions: Option<usize>,
}

#[derive(Clone)]
pub struct PublicParams<'a, E: JubjubEngine, S: ProofScheme<'a>> {
    pub vanilla_params: S::PublicParams,
    pub engine_params: &'a E::Params,
    pub partitions: Option<usize>,
}

/// The CompoundProof trait bundles a proof::ProofScheme and a bellman::Circuit together.
/// It provides methods equivalent to those provided by proof::ProofScheme (setup, prove, verify).
/// See documentation at proof::ProofScheme for details.
/// Implementations should generally only need to supply circuit and generate_public_inputs.
/// The remaining trait methods are used internally and implement the necessary plumbing.
pub trait CompoundProof<'a, E: JubjubEngine, S: ProofScheme<'a>, C: Circuit<E>>
where
    S::PublicParams: ParameterSetIdentifier,
    S::PublicInputs: Clone,
    Self: CacheableParameters<E, C, S::PublicParams>,
{
    // setup is equivalent to ProofScheme::setup.
    fn setup<'b>(sp: &SetupParams<'a, 'b, E, S>) -> Result<PublicParams<'a, E, S>> {
        Ok(PublicParams {
            vanilla_params: S::setup(sp.vanilla_params)?,
            engine_params: sp.engine_params,
            partitions: sp.partitions,
        })
    }

    fn partition_count(public_params: &PublicParams<'a, E, S>) -> usize {
        match public_params.partitions {
            None => 1,
            Some(0) => panic!("cannot specify zero partitions"),
            Some(k) => k,
        }
    }

    /// prove is equivalent to ProofScheme::prove.
    fn prove<'b>(
        pub_params: &'b PublicParams<'a, E, S>,
        pub_in: &'b S::PublicInputs,
        priv_in: &'b S::PrivateInputs,
    ) -> Result<MultiProof<E>> {
        let partitions = Self::partition_count(pub_params);
        let mut shared_groth_params = Vec::with_capacity(partitions);
        let mut groth_proofs = Vec::with_capacity(partitions);

        let partition_count = Self::partition_count(pub_params);

        let vanilla_proofs =
            S::prove_all_partitions(&pub_params.vanilla_params, &pub_in, priv_in, partitions)?;

        assert!(partition_count > 0);
        // This will always run at least once, since there cannot be zero partitions.

        for (k, vanilla_proof) in vanilla_proofs.iter().enumerate() {
            let (groth_proof, groth_params) = Self::circuit_proof(
                pub_in,
                &vanilla_proof,
                &pub_params.vanilla_params,
                pub_params.engine_params,
                Some(k),
            )?;
            shared_groth_params.push(groth_params);
            groth_proofs.push(groth_proof);
        }

        Ok(MultiProof::new(
            groth_proofs,
            shared_groth_params[0].clone(),
        ))
    }

    // verify is equivalent to ProofScheme::verify.
    fn verify(
        public_params: &PublicParams<'a, E, S>,
        public_inputs: &S::PublicInputs,
        multi_proof: &MultiProof<E>,
    ) -> Result<bool> {
        let vanilla_public_params = &public_params.vanilla_params;
        let pvk = groth16::prepare_verifying_key(&multi_proof.groth_params.vk);
        if multi_proof.circuit_proofs.len() != Self::partition_count(public_params) {
            return Ok(false);
        }
        for (k, circuit_proof) in multi_proof.circuit_proofs.iter().enumerate() {
            let inputs =
                Self::generate_public_inputs(public_inputs, vanilla_public_params, Some(k));

            if !groth16::verify_proof(&pvk, &circuit_proof, inputs.as_slice())? {
                return Ok(false);
            }
        }
        Ok(true)
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
        partition: Option<usize>,
    ) -> Result<(groth16::Proof<E>, groth16::Parameters<E>)> {
        // TODO: better random numbers
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // We need to make the circuit repeatedly because we can't clone it.
        // Fortunately, doing so is cheap.
        let make_circuit =
            || Self::circuit(&pub_in, &vanilla_proof, &pub_params, params, partition);

        // TODO: Don't actually generate groth parameters here, certainly not random ones.
        // The parameters will need to have been generated in advance and will be constants
        // associated with a given top-level circuit.
        // They should probably be moved to PublicParams.
        // For now, this is most expedient, since we need the public/private inputs
        // in order to generate a circuit at all.

        let groth_params = Self::get_groth_params(make_circuit(), pub_params, rng)?;

        let groth_proof = groth16::create_random_proof(make_circuit(), &groth_params, rng)?;

        let mut proof_vec = vec![];
        groth_proof.write(&mut proof_vec)?;
        let gp = groth16::Proof::<E>::read(&proof_vec[..])?;

        Ok((gp, groth_params))
    }

    /// generate_public_inputs generates public inputs suitable for use as input during verification
    /// of a proof generated from this CompoundProof's bellman::Circuit (C). These inputs correspond
    /// to those allocated when C is synthesized.
    fn generate_public_inputs(
        pub_in: &S::PublicInputs,
        pub_params: &S::PublicParams,
        partition_k: Option<usize>,
    ) -> Vec<E::Fr>;

    /// circuit constructs an instance of this CompoundProof's bellman::Circuit.
    /// circuit takes PublicInputs, PublicParams, and Proof from this CompoundProof's proof::ProofScheme (S)
    /// and uses them to initialize Circuit fields which will be used to construct public and private
    /// inputs during circuit synthesis.
    fn circuit(
        public_inputs: &S::PublicInputs,
        vanilla_proof: &S::Proof,
        public_param: &S::PublicParams,
        engine_params: &'a E::Params,
        partition_k: Option<usize>,
    ) -> C;

    fn circuit_for_test(
        public_parameters: &PublicParams<'a, E, S>,
        public_inputs: &S::PublicInputs,
        private_inputs: &S::PrivateInputs,
    ) -> (C, Vec<E::Fr>) {
        let vanilla_params = &public_parameters.vanilla_params;
        let partition_count = partitions::partition_count(public_parameters.partitions);
        let vanilla_proofs = S::prove_all_partitions(
            vanilla_params,
            public_inputs,
            private_inputs,
            partition_count,
        )
        .unwrap();
        assert_eq!(vanilla_proofs.len(), partition_count);
        let circuit = Self::circuit(
            &public_inputs,
            &vanilla_proofs[0],
            vanilla_params,
            &public_parameters.engine_params,
            public_parameters.partitions,
        );

        let partition_pub_in = S::with_partition(public_inputs.clone(), Some(0));
        let inputs = Self::generate_public_inputs(&partition_pub_in, vanilla_params, Some(0));

        assert!(
            S::verify_all_partitions(vanilla_params, &public_inputs, &vanilla_proofs).unwrap(),
            "vanilla proof didn't verify"
        );

        (circuit, inputs)
    }
}
