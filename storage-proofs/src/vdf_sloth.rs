use algebra::curves::bls12_377::Bls12_377 as Bls12;
use algebra::fields::bls12_377::Fr;

use crate::crypto::sloth;
use crate::error::Result;
use crate::hasher::pedersen::PedersenDomain;
use crate::parameter_cache::ParameterSetMetadata;
use crate::vdf::Vdf;

/// VDF construction using sloth.
#[derive(Debug, Clone)]
pub struct Sloth {}

#[derive(Debug, Clone)]
pub struct SetupParams {
    pub key: PedersenDomain,
}

#[derive(Debug, Clone)]
pub struct PublicParams {
    pub key: PedersenDomain,
}

impl ParameterSetMetadata for PublicParams {
    fn identifier(&self) -> String {
        format!("vdf_sloth::PublicParams{{key: {:?}; rounds: 0}}", self.key,)
    }

    fn sector_size(&self) -> u64 {
        unimplemented!("required for parameter metadata file generation")
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
        Ok(PublicParams { key: sp.key })
    }

    fn eval(pp: &Self::PublicParams, x: &PedersenDomain) -> Result<(PedersenDomain, Self::Proof)> {
        let key: Fr = pp.key.into();
        let x: Fr = (*x).into();
        let y = sloth::encode::<Bls12>(&key, &x);

        Ok((y.into(), Proof { y: y.into() }))
    }

    fn verify(pp: &Self::PublicParams, x: &PedersenDomain, proof: &Self::Proof) -> Result<bool> {
        let y: Fr = Self::extract_output(proof).into();
        let key: Fr = pp.key.into();
        let decoded: PedersenDomain = sloth::decode::<Bls12>(&key, &y).into();

        Ok(&decoded == x)
    }

    fn key(pp: &self::PublicParams) -> PedersenDomain {
        pp.key
    }

    fn extract_output(proof: &Proof) -> PedersenDomain {
        proof.y
    }
}
