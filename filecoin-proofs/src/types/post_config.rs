use std::path::PathBuf;

use anyhow::Result;
use storage_proofs_core::{
    api_version::ApiVersion,
    merkle::MerkleTreeTrait,
    parameter_cache::{
        parameter_cache_metadata_path, parameter_cache_params_path,
        parameter_cache_verifying_key_path, CacheableParameters,
    },
};
use storage_proofs_post::fallback::{FallbackPoStCircuit, FallbackPoStCompound};

use crate::{
    parameters::{window_post_public_params, winning_post_public_params},
    types::{PaddedBytesAmount, SectorSize, UnpaddedBytesAmount},
};

#[derive(Clone, Debug)]
pub struct PoStConfig {
    pub sector_size: SectorSize,
    pub challenge_count: usize,
    pub sector_count: usize,
    pub typ: PoStType,
    /// High priority (always runs on GPU) == true
    pub priority: bool,
    pub api_version: ApiVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoStType {
    Winning,
    Window,
}

impl From<PoStConfig> for PaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        let PoStConfig { sector_size, .. } = x;
        PaddedBytesAmount::from(sector_size)
    }
}

impl From<PoStConfig> for UnpaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        let PoStConfig { sector_size, .. } = x;
        PaddedBytesAmount::from(sector_size).into()
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
    pub fn get_cache_identifier<Tree: 'static + MerkleTreeTrait>(&self) -> Result<String> {
        match self.typ {
            PoStType::Winning => {
                let params = winning_post_public_params::<Tree>(self)?;

                Ok(<FallbackPoStCompound<Tree> as CacheableParameters<
                    FallbackPoStCircuit<Tree>,
                    _,
                >>::cache_identifier(&params))
            }
            PoStType::Window => {
                let params = window_post_public_params::<Tree>(self)?;

                Ok(<FallbackPoStCompound<Tree> as CacheableParameters<
                    FallbackPoStCircuit<Tree>,
                    _,
                >>::cache_identifier(&params))
            }
        }
    }

    pub fn get_cache_metadata_path<Tree: 'static + MerkleTreeTrait>(&self) -> Result<PathBuf> {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_metadata_path(&id))
    }

    pub fn get_cache_verifying_key_path<Tree: 'static + MerkleTreeTrait>(&self) -> Result<PathBuf> {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_verifying_key_path(&id))
    }

    pub fn get_cache_params_path<Tree: 'static + MerkleTreeTrait>(&self) -> Result<PathBuf> {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_params_path(&id))
    }
}
