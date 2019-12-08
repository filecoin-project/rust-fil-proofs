use rayon::prelude::*;

use anyhow::{ensure, Context};
use bellperson::{groth16, Circuit};
use fil_sapling_crypto::jubjub::JubjubEngine;
use log::info;
use rand::{rngs::OsRng, RngCore};

use crate::circuit::multi_proof::MultiProof;
use crate::error::Result;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::partitions;
use crate::proof::ProofScheme;
use crate::settings;

#[derive(Clone)]
pub struct SetupParams<'a, S: ProofScheme<'a>> {
    pub vanilla_params: <S as ProofScheme<'a>>::SetupParams,
    pub partitions: Option<usize>,
}

#[derive(Clone)]
pub struct PublicParams<'a, S: ProofScheme<'a>> {
    pub vanilla_params: S::PublicParams,
    pub partitions: Option<usize>,
}

/// CircuitComponent exists so parent components can pass private inputs to their subcomponents
/// when calling CompoundProof::circuit directly. In general, there are no internal private inputs,
/// and a default value will be passed. CompoundProof::circuit implementations should exhibit
/// default behavior when passed a default ComponentPrivateinputs.
pub trait CircuitComponent {
    type ComponentPrivateInputs: Default + Clone;
}

/// The CompoundProof trait bundles a proof::ProofScheme and a bellperson::Circuit together.
/// It provides methods equivalent to those provided by proof::ProofScheme (setup, prove, verify).
/// See documentation at proof::ProofScheme for details.
/// Implementations should generally only need to supply circuit and generate_public_inputs.
/// The remaining trait methods are used internally and implement the necessary plumbing.
pub trait CompoundProof<'a, E: JubjubEngine, S: ProofScheme<'a>, C: Circuit<E> + CircuitComponent>
where
    S::Proof: Sync + Send,
    S::PublicParams: ParameterSetMetadata + Sync + Send,
    S::PublicInputs: Clone + Sync,
    Self: CacheableParameters<E, C, S::PublicParams>,
{
    // setup is equivalent to ProofScheme::setup.
    fn setup(sp: &SetupParams<'a, S>) -> Result<PublicParams<'a, S>>
    where
        E::Params: Sync,
    {
        Ok(PublicParams {
            vanilla_params: S::setup(&sp.vanilla_params)?,
            partitions: sp.partitions,
        })
    }

    fn partition_count(public_params: &PublicParams<'a, S>) -> usize {
        match public_params.partitions {
            None => 1,
            Some(0) => panic!("cannot specify zero partitions"),
            Some(k) => k,
        }
    }

    /// prove is equivalent to ProofScheme::prove.
    fn prove<'b>(
        pub_params: &PublicParams<'a, S>,
        pub_in: &S::PublicInputs,
        priv_in: &S::PrivateInputs,
        groth_params: &'b groth16::Parameters<E>,
    ) -> Result<MultiProof<'b, E>>
    where
        E::Params: Sync,
    {
        let partitions = Self::partition_count(pub_params);
        let partition_count = Self::partition_count(pub_params);

        // This will always run at least once, since there cannot be zero partitions.
        ensure!(partition_count > 0, "There must be partitions");

        info!("vanilla_proof:start");
        let vanilla_proofs =
            S::prove_all_partitions(&pub_params.vanilla_params, &pub_in, priv_in, partitions)?;

        info!("vanilla_proof:finish");

        let sanity_check =
            S::verify_all_partitions(&pub_params.vanilla_params, &pub_in, &vanilla_proofs)?;
        ensure!(sanity_check, "sanity check failed");

        // Use a custom pool for this, so we can control the number of threads being used.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(settings::SETTINGS.lock().unwrap().num_proving_threads)
            .build()
            .context("failed to build thread pool")?;

        info!("snark_proof:start");
        let groth_proofs: Result<Vec<_>> = pool.install(|| {
            vanilla_proofs
                .par_iter()
                .map(|vanilla_proof| {
                    Self::circuit_proof(
                        pub_in,
                        &vanilla_proof,
                        &pub_params.vanilla_params,
                        groth_params,
                    )
                })
                .collect()
        });
        info!("snark_proof:finish");

        Ok(MultiProof::new(groth_proofs?, &groth_params.vk))
    }

    // verify is equivalent to ProofScheme::verify.
    fn verify<'b>(
        public_params: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        multi_proof: &MultiProof<'b, E>,
        requirements: &S::Requirements,
    ) -> Result<bool> {
        let vanilla_public_params = &public_params.vanilla_params;
        let pvk = groth16::prepare_verifying_key(&multi_proof.verifying_key);
        if multi_proof.circuit_proofs.len() != Self::partition_count(public_params) {
            return Ok(false);
        }

        if !<S as ProofScheme>::satisfies_requirements(
            &public_params.vanilla_params,
            requirements,
            multi_proof.circuit_proofs.len(),
        ) {
            return Ok(false);
        }

        for (k, circuit_proof) in multi_proof.circuit_proofs.iter().enumerate() {
            let inputs =
                Self::generate_public_inputs(public_inputs, vanilla_public_params, Some(k))?;

            if !groth16::verify_proof(&pvk, &circuit_proof, inputs.as_slice())? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// circuit_proof creates and synthesizes a circuit from concrete params/inputs, then generates a
    /// groth proof from it. It returns a groth proof.
    /// circuit_proof is used internally and should neither be called nor implemented outside of
    /// default trait methods.
    fn circuit_proof(
        pub_in: &S::PublicInputs,
        vanilla_proof: &S::Proof,
        pub_params: &S::PublicParams,
        groth_params: &groth16::Parameters<E>,
    ) -> Result<groth16::Proof<E>> {
        let mut rng = OsRng;

        // We need to make the circuit repeatedly because we can't clone it.
        // Fortunately, doing so is cheap.
        let make_circuit = || {
            Self::circuit(
                &pub_in,
                C::ComponentPrivateInputs::default(),
                &vanilla_proof,
                &pub_params,
            )
        };

        let groth_proof = groth16::create_random_proof(make_circuit()?, groth_params, &mut rng)?;

        let mut proof_vec = vec![];
        groth_proof.write(&mut proof_vec)?;
        let gp = groth16::Proof::<E>::read(&proof_vec[..])?;

        Ok(gp)
    }

    /// generate_public_inputs generates public inputs suitable for use as input during verification
    /// of a proof generated from this CompoundProof's bellperson::Circuit (C). These inputs correspond
    /// to those allocated when C is synthesized.
    fn generate_public_inputs(
        pub_in: &S::PublicInputs,
        pub_params: &S::PublicParams,
        partition_k: Option<usize>,
    ) -> Result<Vec<E::Fr>>;

    /// circuit constructs an instance of this CompoundProof's bellperson::Circuit.
    /// circuit takes PublicInputs, PublicParams, and Proof from this CompoundProof's proof::ProofScheme (S)
    /// and uses them to initialize Circuit fields which will be used to construct public and private
    /// inputs during circuit synthesis.
    fn circuit(
        public_inputs: &S::PublicInputs,
        component_private_inputs: C::ComponentPrivateInputs,
        vanilla_proof: &S::Proof,
        public_param: &S::PublicParams,
    ) -> Result<C>;

    fn blank_circuit(public_params: &S::PublicParams) -> C;

    fn groth_params<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
    ) -> Result<groth16::Parameters<E>> {
        Self::get_groth_params(rng, Self::blank_circuit(public_params), public_params)
    }

    fn verifying_key<R: RngCore>(
        rng: Option<&mut R>,
        public_params: &S::PublicParams,
    ) -> Result<groth16::VerifyingKey<E>> {
        Self::get_verifying_key(rng, Self::blank_circuit(public_params), public_params)
    }

    fn circuit_for_test(
        public_parameters: &PublicParams<'a, S>,
        public_inputs: &S::PublicInputs,
        private_inputs: &S::PrivateInputs,
    ) -> Result<(C, Vec<E::Fr>)> {
        let vanilla_params = &public_parameters.vanilla_params;
        let partition_count = partitions::partition_count(public_parameters.partitions);
        let vanilla_proofs = S::prove_all_partitions(
            vanilla_params,
            public_inputs,
            private_inputs,
            partition_count,
        )
        .context("failed to generate partition proofs")?;

        ensure!(
            vanilla_proofs.len() == partition_count,
            "Vanilla proofs didn't match number of partitions."
        );

        let partitions_are_verified =
            S::verify_all_partitions(vanilla_params, &public_inputs, &vanilla_proofs)
                .context("failed to verify partition proofs")?;

        ensure!(partitions_are_verified, "Vanilla proof didn't verify.");

        // Some(0) because we only return a circuit and inputs for the first partition.
        // It would be more thorough to return all, though just checking one is probably
        // fine for verifying circuit construction.
        let partition_pub_in = S::with_partition(public_inputs.clone(), Some(0));
        let inputs = Self::generate_public_inputs(&partition_pub_in, vanilla_params, Some(0))?;

        let circuit = Self::circuit(
            &partition_pub_in,
            C::ComponentPrivateInputs::default(),
            &vanilla_proofs[0],
            vanilla_params,
        )?;

        Ok((circuit, inputs))
    }
}
