use crate::error::Result;
use crate::hasher::Domain;

/// Generic trait to represent any Verfiable Delay Function (VDF).
pub trait Vdf<T: Domain>: Clone + ::std::fmt::Debug {
    type SetupParams: Clone + ::std::fmt::Debug;
    type PublicParams: Clone + ::std::fmt::Debug;
    type Proof: Clone + ::std::fmt::Debug;

    fn setup(_: &Self::SetupParams) -> Result<Self::PublicParams>;
    fn eval(_: &Self::PublicParams, _: &T) -> Result<(T, Self::Proof)>;
    fn verify(_: &Self::PublicParams, _: &T, _: &T, _: &Self::Proof) -> Result<bool>;
}
