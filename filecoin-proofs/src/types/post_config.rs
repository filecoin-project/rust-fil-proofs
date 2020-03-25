use std::path::PathBuf;

use anyhow::Result;
use paired::bls12_381::Bls12;
use storage_proofs::parameter_cache::{self, CacheableParameters};
use storage_proofs::post::election::{ElectionPoStCircuit, ElectionPoStCompound};

use crate::constants::DefaultTreeHasher;
use crate::types::*;

#[derive(Clone, Debug)]
pub struct PoStConfig {
    pub sector_size: SectorSize,
    pub challenge_count: usize,
    pub sector_count: usize,
    pub typ: PoStType,
    /// High priority (always runs on GPU) == true
    pub priority: bool,
}

#[derive(Debug, Clone)]
pub enum PoStType {
    Election,
    Winning,
    Window,
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
    pub fn padded_sector_size(&self) -> PaddedBytesAmount {
        PaddedBytesAmount::from(self.sector_size)
    }

    pub fn unpadded_sector_size(&self) -> UnpaddedBytesAmount {
        PaddedBytesAmount::from(self.sector_size).into()
    }

    /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
    pub fn get_cache_identifier(&self) -> Result<String> {
        match self.typ {
            PoStType::Election => {
                let params = crate::parameters::election_post_public_params(self)?;

                Ok(
                    <ElectionPoStCompound<DefaultTreeHasher> as CacheableParameters<
                        Bls12,
                        ElectionPoStCircuit<_, DefaultTreeHasher>,
                        _,
                    >>::cache_identifier(&params),
                )
            }
            PoStType::Winning => unimplemented!(),
            PoStType::Window => unimplemented!(),
        }
    }

    pub fn get_cache_metadata_path(&self) -> Result<PathBuf> {
        let id = self.get_cache_identifier()?;
        Ok(parameter_cache::parameter_cache_metadata_path(&id))
    }

    pub fn get_cache_verifying_key_path(&self) -> Result<PathBuf> {
        let id = self.get_cache_identifier()?;
        Ok(parameter_cache::parameter_cache_verifying_key_path(&id))
    }

    pub fn get_cache_params_path(&self) -> Result<PathBuf> {
        let id = self.get_cache_identifier()?;
        Ok(parameter_cache::parameter_cache_params_path(&id))
    }
}
