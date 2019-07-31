use paired::bls12_381::Bls12;
use storage_proofs::circuit::vdf_post::{VDFPoStCircuit, VDFPostCompound};
use storage_proofs::parameter_cache::CacheableParameters;

use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct PoStConfig(pub SectorSize, pub PoStProofPartitions);

impl From<PoStConfig> for PaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(s, _) => PaddedBytesAmount::from(s),
        }
    }
}

impl From<PoStConfig> for UnpaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(s, _) => PaddedBytesAmount::from(s).into(),
        }
    }
}

impl From<PoStConfig> for PoStProofPartitions {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(_, p) => p,
        }
    }
}

impl PoStConfig {
    /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
    pub fn get_cache_identifier(&self) -> String {
        let params = crate::parameters::post_public_params(*self);

        <VDFPostCompound as CacheableParameters<Bls12, VDFPoStCircuit<_>, _>>::cache_identifier(
            &params,
        )
    }
}
