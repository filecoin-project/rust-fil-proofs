use pairing::bls12_381::{Bls12, Fr};

use crypto::sloth;
use error::Result;
use hasher::pedersen::PedersenDomain;
use vdf::Vdf;

/// VDF construction using sloth.
#[derive(Debug, Clone)]
pub struct Sloth {}

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

#[derive(Debug, Clone)]
pub struct Proof {}

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

        Ok((y.into(), Proof {}))
    }

    fn verify(
        pp: &Self::PublicParams,
        x: &PedersenDomain,
        y: &PedersenDomain,
        _proof: &Self::Proof,
    ) -> Result<bool> {
        let y: Fr = (*y).into();
        let key: Fr = pp.key.into();
        let decoded: PedersenDomain = sloth::decode::<Bls12>(&key, &y, pp.rounds).into();

        Ok(&decoded == x)
    }
}
