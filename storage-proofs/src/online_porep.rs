use std::marker::PhantomData;

use error::Result;
use hasher::Domain;
use proof::ProofScheme;

#[derive(Debug, Clone)]
pub struct SetupParams {}

#[derive(Debug, Clone)]
pub struct PublicParams {}

#[derive(Debug, Clone)]
pub struct PublicInputs<'a, T: Domain> {
    pub challenges: &'a [T],
    pub commitment: T,
}

#[derive(Debug, Clone)]
pub struct PrivateInputs<'a> {
    pub replica: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Proof {}

impl Proof {
    pub fn leafs(&self) -> &[&[u8]] {
        unimplemented!();
    }
}

#[derive(Debug, Clone)]
pub struct OnlinePoRep<T: Domain> {
    _t: PhantomData<T>,
}

impl<'a, T: 'a + Domain> ProofScheme<'a> for OnlinePoRep<T> {
    type PublicParams = PublicParams;
    type SetupParams = SetupParams;
    type PublicInputs = PublicInputs<'a, T>;
    type PrivateInputs = PrivateInputs<'a>;
    type Proof = Proof;

    fn setup(_sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        unimplemented!();
    }

    fn prove<'b>(
        _pub_params: &'b Self::PublicParams,
        _pub_inputs: &'b Self::PublicInputs,
        _priv_inputs: &'b Self::PrivateInputs,
    ) -> Result<Self::Proof> {
        unimplemented!();
    }

    fn verify(
        _pub_params: &Self::PublicParams,
        _pub_inputs: &Self::PublicInputs,
        _proof: &Self::Proof,
    ) -> Result<bool> {
        unimplemented!();
    }
}
