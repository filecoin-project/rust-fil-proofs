use error::Result;
use hasher::Domain;

/// Generic trait to represent any Verfiable Delay Function (VDF).
pub trait Vdf<T: Domain>: Clone + ::std::fmt::Debug {
    type SetupParams: Clone + ::std::fmt::Debug;
    type PublicParams: Clone + ::std::fmt::Debug;
    type Proof: Clone + ::std::fmt::Debug;

    fn setup(&Self::SetupParams) -> Result<Self::PublicParams>;
    fn eval(&Self::PublicParams, &T) -> Result<(T, Self::Proof)>;
    fn verify(&Self::PublicParams, &T, &T, &Self::Proof) -> Result<bool>;
}
