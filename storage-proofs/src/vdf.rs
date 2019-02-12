use crate::error::Result;
use crate::hasher::Domain;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;

/// Generic trait to represent any Verfiable Delay Function (VDF).
pub trait Vdf<T: Domain>: Clone + ::std::fmt::Debug {
    type SetupParams: Clone + ::std::fmt::Debug;
    type PublicParams: Clone + ::std::fmt::Debug;
    type Proof: Clone + ::std::fmt::Debug + Serialize + DeserializeOwned;

    fn setup(setup_params: &Self::SetupParams) -> Result<Self::PublicParams>;
    fn eval(public_params: &Self::PublicParams, input: &T) -> Result<(T, Self::Proof)>;
    fn verify(public_params: &Self::PublicParams, input: &T, proof: &Self::Proof) -> Result<bool>;

    fn key(pp: &Self::PublicParams) -> T;
    fn rounds(pp: &Self::PublicParams) -> usize;
    fn extract_output(proof: &Self::Proof) -> T;
}
