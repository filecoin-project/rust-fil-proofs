use error::Result;
use hasher::Domain;

/// Generic trait to represent any Verfiable Delay Function (VDF).
pub trait Vdf<T: Domain>: Clone {
    type SetupParams: Clone;
    type PublicParams: Clone;
    type Proof: Clone;

    fn setup(&Self::SetupParams) -> Result<Self::PublicParams>;
    fn eval(&Self::PublicParams, &T) -> Result<(T, Self::Proof)>;
    fn verify(&Self::PublicParams, &T, &T, &Self::Proof) -> Result<bool>;
}
