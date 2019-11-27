use std::path::PathBuf;

use anyhow::Result;

use paired::bls12_381::Bls12;
use storage_proofs::circuit::election_post::{ElectionPoStCircuit, ElectionPoStCompound};
use storage_proofs::drgraph::DefaultTreeHasher;
use storage_proofs::parameter_cache::{self, CacheableParameters};

use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct PoStConfig {
    pub sector_size: SectorSize,
}

impl From<PoStConfig> for PaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig { sector_size, .. } => PaddedBytesAmount::from(sector_size),
        }
    }
}

impl From<PoStConfig> for UnpaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig { sector_size, .. } => PaddedBytesAmount::from(sector_size).into(),
        }
    }
}

impl PoStConfig {
    /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
    pub fn get_cache_identifier(self) -> Result<String> {
        let params = crate::parameters::post_public_params(self)?;

        Ok(
            <ElectionPoStCompound<DefaultTreeHasher> as CacheableParameters<
                Bls12,
                ElectionPoStCircuit<_, DefaultTreeHasher>,
                _,
            >>::cache_identifier(&params),
        )
    }

    pub fn get_cache_metadata_path(self) -> Result<PathBuf> {
        let id = self.get_cache_identifier()?;
        Ok(parameter_cache::parameter_cache_metadata_path(&id))
    }

    pub fn get_cache_verifying_key_path(self) -> Result<PathBuf> {
        let id = self.get_cache_identifier()?;
        Ok(parameter_cache::parameter_cache_verifying_key_path(&id))
    }

    pub fn get_cache_params_path(self) -> Result<PathBuf> {
        let id = self.get_cache_identifier()?;
        Ok(parameter_cache::parameter_cache_params_path(&id))
    }
}
