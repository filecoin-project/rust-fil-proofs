
use error::Result;


/// The methods that any proof scheme needs to implement
pub trait ProofScheme<'a> {
    type PublicParams;
    type SetupParams;
    type PublicInputs;
    type PrivateInputs;
    type Proof;

    fn setup(&Self::SetupParams) -> Result<Self::PublicParams>;
    fn prove(&Self::PublicParams, &Self::PublicInputs, &Self::PrivateInputs)
        -> Result<Self::Proof>;
    fn verify(&Self::PublicParams, &Self::PublicInputs, &Self::Proof) -> Result<bool>;
}
