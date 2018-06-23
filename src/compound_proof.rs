use bellman::groth16;
use bellman::Circuit;
use error::Result;
use pairing::bls12_381::Bls12;
use pairing::Engine;
use proof::ProofScheme;
use rand::{SeedableRng, XorShiftRng};

pub trait CompoundProof<'a, E: Engine>
where
    Self: Circuit<E>,
    Self::Circuit: Circuit<E>,
    Self::VanillaProof: ProofScheme<'a>,
{
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
    ) -> Result<(
        groth16::Proof<Bls12>,
        <Self::VanillaProof as ProofScheme<'a>>::Proof,
    )>
    where
        &'a Self: Circuit<Bls12>,
    {
        let vanilla_proof =
            <Self::VanillaProof as ProofScheme<'a>>::prove(&pub_params, &pub_in, &priv_in)?;

        self.circuit_proof(vanilla_proof)
    }
    fn circuit_proof(
        &'a self,
        vanilla_proof: <Self::VanillaProof as ProofScheme<'a>>::Proof,
    ) -> Result<(
        groth16::Proof<Bls12>,
        <Self::VanillaProof as ProofScheme<'a>>::Proof,
    )>
    where
        &'a Self: Circuit<Bls12>,
    {
        let proof_copy = vanilla_proof.clone();

        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let groth_params = groth16::generate_random_parameters::<Bls12, _, _>(self, rng)?;

        let groth_proof = groth16::create_random_proof(self, &groth_params, rng)?;
        let mut proof_vec = vec![];
        groth_proof.write(&mut proof_vec)?;
        let gp = groth16::Proof::<Bls12>::read(&proof_vec[..])?;

        Ok((gp, proof_copy))
    }
}
