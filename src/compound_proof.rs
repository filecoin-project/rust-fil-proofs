use bellman::groth16::{self, Proof};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
use circuit;
use circuit::por;
use drgporep;
use error;
use merklepor;
use pairing::bls12_381::Bls12;
use pairing::Engine;
use proof::ProofScheme;
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

pub trait CompoundProof<'a, E: Engine>
where
    Self::Circuit: Circuit<E>,
    Self::VanillaProof: ProofScheme<'a>,
{
    type Circuit: Circuit<E>;
    type VanillaProof: ProofScheme<'a>;

    fn setup(
        setup_params: &<Self::VanillaProof as ProofScheme<'a>>::SetupParams,
    ) -> error::Result<<Self::VanillaProof as ProofScheme<'a>>::PublicParams> {
        <Self::VanillaProof as ProofScheme<'a>>::setup(setup_params)
    }

    fn prove(
        pub_params: <Self::VanillaProof as ProofScheme<'a>>::PublicParams,
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        priv_in: <Self::VanillaProof as ProofScheme<'a>>::PrivateInputs,
    ) -> error::Result<(
        groth16::Proof<E>,
        <Self::VanillaProof as ProofScheme<'a>>::Proof,
    )> {
        let vanilla_proof =
            <Self::VanillaProof as ProofScheme<'a>>::prove(&pub_params, &pub_in, &priv_in)?;

        Ok(Self::circuit_proof(pub_in, vanilla_proof)?)
    }

    fn circuit_proof_constraints(
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        vanilla_proof: <Self::VanillaProof as ProofScheme<'a>>::Proof,
    ) -> error::Result<circuit::test::TestConstraintSystem<E>>; //error::Result<Self::Circuit>;

    fn circuit_proof(
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        vanilla_proof: <Self::VanillaProof as ProofScheme<'a>>::Proof,
    ) -> error::Result<(
        groth16::Proof<E>,
        <Self::VanillaProof as ProofScheme<'a>>::Proof,
    )>;

    fn verify(
        pub_params: <Self::VanillaProof as ProofScheme<'a>>::PublicParams,
        pub_in: <Self::VanillaProof as ProofScheme<'a>>::PublicInputs,
        proof: (
            groth16::Proof<E>,
            <Self::VanillaProof as ProofScheme<'a>>::Proof,
        ),
    ) -> error::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]

    fn test_compound_proof() {}
}
