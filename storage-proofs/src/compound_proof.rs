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

// FIXME: We can probably get rid of this, since in the common case we only ever pass a default value.
// Components with private inputs should use a helper (Compononet::Synthesize) to pass any private inputs needed.
pub trait CircuitComponent {
    type PrivateInputs: Default + Clone;
}

/// The CompoundProof trait bundles a proof::ProofScheme and a bellman::Circuit together.
/// It provides methods equivalent to those provided by proof::ProofScheme (setup, prove, verify).
/// See documentation at proof::ProofScheme for details.
/// Implementations should generally only need to supply circuit and generate_public_inputs.
/// The remaining trait methods are used internally and implement the necessary plumbing.
pub trait CompoundProof<'a, E: JubjubEngine, S: ProofScheme<'a>, C: Circuit<E> + CircuitComponent>
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
        groth_params: Option<groth16::Parameters<E>>,
    ) -> Result<MultiProof<E>> {
        let partitions = Self::partition_count(pub_params);
        let mut shared_groth_params = groth_params;
        let mut groth_proofs = Vec::with_capacity(partitions);

        let partition_count = Self::partition_count(pub_params);

        let vanilla_proofs =
            S::prove_all_partitions(&pub_params.vanilla_params, &pub_in, priv_in, partitions)?;

        assert!(partition_count > 0);
        // This will always run at least once, since there cannot be zero partitions.

        for vanilla_proof in vanilla_proofs.iter() {
            let (groth_proof, groth_params) = Self::circuit_proof(
                pub_in,
                C::PrivateInputs::default(),
                &vanilla_proof,
                &pub_params.vanilla_params,
                pub_params.engine_params,
                &shared_groth_params,
            )?;
            if groth_params.is_some() {
                shared_groth_params = groth_params;
            }
            groth_proofs.push(groth_proof);
        }

        Ok(MultiProof::new(
            groth_proofs,
            shared_groth_params.unwrap().clone(),
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
            println!("????????????????");
            let inputs =
                Self::generate_public_inputs(public_inputs, vanilla_public_params, Some(k));

            if !groth16::verify_proof(&pvk, &circuit_proof, inputs.as_slice())? {
                println!("!!!!!!!!!!!!!!!!!!!!!");
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// circuit_proof creates and synthesizes a circuit from concrete params/inputs, then generates a
    /// groth proof from it. It returns a tuple of the groth proof and params.
    /// circuit_proof is used internally and should neither be called nor implemented outside of
    /// default trait methods.
    ///
    /// If groth_params are not supplied, they will be generated and returned.
    /// If groth_params *are* supplied, they will not be generated, and None will be returned.
    fn circuit_proof<'b>(
        pub_in: &S::PublicInputs,
        component_priv_in: C::PrivateInputs,
        vanilla_proof: &S::Proof,
        pub_params: &'b S::PublicParams,
        params: &'a E::Params,
        groth_params: &Option<groth16::Parameters<E>>,
    ) -> Result<(groth16::Proof<E>, Option<groth16::Parameters<E>>)> {
        // TODO: better random numbers
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        // We need to make the circuit repeatedly because we can't clone it.
        // Fortunately, doing so is cheap.
        let make_circuit = || {
            Self::circuit(
                &pub_in,
                component_priv_in.clone(),
                //C::PrivateInputs::default(),
                &vanilla_proof,
                &pub_params,
                params,
            )
        };

        // TODO: Don't actually generate groth parameters here, certainly not random ones.
        // The parameters will need to have been generated in advance and will be constants
        // associated with a given top-level circuit.
        // They should probably be moved to PublicParams.
        // For now, this is most expedient, since we need the public/private inputs
        // in order to generate a circuit at all.

        let (groth_proof, groth_params_to_return) = match groth_params {
            Some(gp) => (groth16::create_random_proof(make_circuit(), gp, rng)?, None),
            None => {
                let gp = Self::get_groth_params(make_circuit(), pub_params, rng)?;
                (
                    groth16::create_random_proof(make_circuit(), &gp, rng)?,
                    Some(gp),
                )
            }
        };

        let mut proof_vec = vec![];
        groth_proof.write(&mut proof_vec)?;
        let gp = groth16::Proof::<E>::read(&proof_vec[..])?;

        // Exactly one of the input and returned groth_params should be None.
        assert!(groth_params.is_none() ^ groth_params_to_return.is_none());

        Ok((gp, groth_params_to_return))
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
        component_private_inputs: C::PrivateInputs,
        vanilla_proof: &S::Proof,
        public_param: &S::PublicParams,
        engine_params: &'a E::Params,
    ) -> C;

    fn blank_circuit(_public_param: &S::PublicParams, _engine_params: &'a E::Params) -> C {
        unimplemented!();
    }

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

        assert!(
            S::verify_all_partitions(vanilla_params, &public_inputs, &vanilla_proofs).unwrap(),
            "vanilla proof didn't verify"
        );

        // Some(0) because we only return a circuit and inputs for the first partition.
        // It would be more thorough to return all, though just checking one is probably
        // fine for verifying circuit construction.
        let partition_pub_in = S::with_partition(public_inputs.clone(), Some(0));
        let inputs = Self::generate_public_inputs(&partition_pub_in, vanilla_params, Some(0));

        let circuit = Self::circuit(
            &partition_pub_in,
            C::PrivateInputs::default(),
            &vanilla_proofs[0],
            vanilla_params,
            &public_parameters.engine_params,
        );

        (circuit, inputs)
    }
}
