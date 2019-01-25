use pairing::bls12_381::{Bls12, Fr};

use crate::crypto::sloth;
use crate::error::Result;
use crate::hasher::pedersen::PedersenDomain;
use crate::parameter_cache::ParameterSetIdentifier;
use crate::vdf::Vdf;

/// VDF construction using sloth.
#[derive(Debug, Clone)]
pub struct Sloth {}

unsafe impl Sync for Sloth {}
unsafe impl Send for Sloth {}

#[derive(Debug, Clone)]
pub struct SetupParams {
    pub key: PedersenDomain,
    pub rounds: usize,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    pub key: PedersenDomain,
    pub rounds: usize,
}

impl ParameterSetIdentifier for PublicParams {
    fn parameter_set_identifier(&self) -> String {
        format!(
            "vdf_sloth::PublicParams{{key: {:?}; rounds: {}}}",
            self.key, self.rounds
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    y: PedersenDomain,
}

impl Vdf<PedersenDomain> for Sloth {
    type SetupParams = SetupParams;
    type PublicParams = PublicParams;
    type Proof = Proof;

    fn setup(sp: &Self::SetupParams) -> Result<Self::PublicParams> {
        Ok(PublicParams {
            key: sp.key,
            rounds: sp.rounds,
        })
    }

    fn eval(pp: &Self::PublicParams, x: &PedersenDomain) -> Result<(PedersenDomain, Self::Proof)> {
        let key: Fr = pp.key.into();
        let x: Fr = (*x).into();
        let y = sloth::encode::<Bls12>(&key, &x, pp.rounds);

        Ok((y.into(), Proof { y: y.into() }))
    }

    fn verify(pp: &Self::PublicParams, x: &PedersenDomain, proof: &Self::Proof) -> Result<bool> {
        let y: Fr = Self::extract_output(proof).into();
        let key: Fr = pp.key.into();
        let decoded: PedersenDomain = sloth::decode::<Bls12>(&key, &y, pp.rounds).into();

        Ok(&decoded == x)
    }

    fn key(pp: &self::PublicParams) -> PedersenDomain {
        pp.key
    }
    fn rounds(pp: &self::PublicParams) -> usize {
        pp.rounds
    }
    fn extract_output(proof: &Proof) -> PedersenDomain {
        proof.y
    }
}
