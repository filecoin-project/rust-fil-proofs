use bellman::groth16;
use bellman::Circuit;
use error::Result;
use pairing::Engine;
use proof::ProofScheme;

pub trait CompoundProof<'a, E: Engine>
where
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
        pub_params: <Self::VanillaProof as ProofScheme<'a>>::PublicParams,
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        priv_in: <Self::VanillaProof as ProofScheme<'a>>::PrivateInputs,
    ) -> Result<(
        groth16::Proof<E>,
        <Self::VanillaProof as ProofScheme<'a>>::Proof,
    )> {
        let vanilla_proof =
            <Self::VanillaProof as ProofScheme<'a>>::prove(&pub_params, &pub_in, &priv_in)?;

        Self::circuit_proof(pub_in, vanilla_proof)
    }

    fn circuit_proof(
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        vanilla_proof: <Self::VanillaProof as ProofScheme<'a>>::Proof,
    ) -> Result<(
        groth16::Proof<E>,
        <Self::VanillaProof as ProofScheme<'a>>::Proof,
    )>;

    fn verify(
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        proof: (
            groth16::Proof<E>,
            <Self::VanillaProof as ProofScheme<'a>>::Proof,
        ),
    ) -> Result<bool>;
}
