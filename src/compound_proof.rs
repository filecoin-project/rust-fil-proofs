use bellman::groth16;
use bellman::Circuit;
use error::Result;
use pairing::bls12_381::Bls12;
use pairing::Engine;
use proof::ProofScheme;
use rand::{SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::JubjubEngine;

pub trait CompoundProof<'a, 'b, E: JubjubEngine> {
    type Circuit: Circuit<E>;
    type VanillaProof: ProofScheme<'a>;

    fn setup(
        setup_params: &<Self::VanillaProof as ProofScheme<'a>>::SetupParams,
    ) -> Result<<Self::VanillaProof as ProofScheme<'a>>::PublicParams> {
        <Self::VanillaProof as ProofScheme<'a>>::setup(setup_params)
    }

    fn prove(
        &'a self,
        pub_params: <Self::VanillaProof as ProofScheme<'a>>::PublicParams,
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        priv_in: <Self::VanillaProof as ProofScheme<'a>>::PrivateInputs,
        params: E::Params,
    ) -> Result<(
        groth16::Proof<Bls12>,
        <Self::VanillaProof as ProofScheme<'a>>::Proof,
        groth16::Parameters<Bls12>,
    )>
    where
        &'a Self: Circuit<Bls12>,
        <Self::VanillaProof as ProofScheme<'a>>::Proof: 'b,
    {
        let vanilla_proof =
            <Self::VanillaProof as ProofScheme<'a>>::prove(&pub_params, &pub_in, &priv_in)?;

        let (circuit_proof, groth_params) = self.circuit_proof(pub_in, vanilla_proof, params)?;
        Ok((circuit_proof, vanilla_proof, groth_params))
    }

    fn circuit_proof(
        &'a self,
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        vanilla_proof: <Self::VanillaProof as ProofScheme<'a>>::Proof,
        params: E::Params,
    ) -> Result<(groth16::Proof<Bls12>, groth16::Parameters<Bls12>)>
    where
        E: JubjubEngine,
        &'a Self: Circuit<Bls12>,
    {
        let proof_copy = vanilla_proof.clone();

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let groth_params = groth16::generate_random_parameters::<Bls12, _, _>(self, rng)?;

        let circuit = Self::make_circuit(&pub_in, &vanilla_proof, params);

        let groth_proof = groth16::create_random_proof(self, &groth_params, rng)?;
        let mut proof_vec = vec![];
        groth_proof.write(&mut proof_vec)?;
        let gp = groth16::Proof::<Bls12>::read(&proof_vec[..])?;

        Ok((gp, groth_params))
    }

    fn make_circuit(
        public_inputs: &<Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        vanilla_proof: &<Self::VanillaProof as ProofScheme<'a>>::Proof,
        params: E::Params,
    ) -> Self::Circuit;

    fn verify(
        &'a self,
        groth_params: groth16::Parameters<Bls12>,
        vanilla_proof: &<Self::VanillaProof as ProofScheme<'a>>::Proof,
        proof: groth16::Proof<Bls12>,
        public_inputs: &<Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
    ) -> Result<bool>
    where
        &'a Self: Circuit<Bls12>,
    {
        let pvk = groth16::prepare_verifying_key(&groth_params.vk);
        let inputs = Self::inputize(public_inputs, vanilla_proof);

        Ok(groth16::verify_proof(&pvk, &proof, inputs.as_slice())?)
    }

    fn inputize(
        pub_in: &<Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        vanilla_proof: &<Self::VanillaProof as ProofScheme<'a>>::Proof,
    ) -> Vec<<Bls12 as Engine>::Fr>;
}
