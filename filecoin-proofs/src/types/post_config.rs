use std::path::PathBuf;

use anyhow::Result;
use blstrs::Scalar as Fr;
use filecoin_hashers::R1CSHasher;
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

impl From<PoStConfig> for SectorSize {
    fn from(x: PoStConfig) -> Self {
        let PoStConfig { sector_size, .. } = x;
        sector_size
    }
}

impl PoStConfig {
    pub fn new_halo2(
        sector_size: SectorSize,
        typ: PoStType,
        priority: bool,
        api_version: ApiVersion,
    ) -> Self {
        use storage_proofs_post::halo2::{window, winning};

        let sector_nodes = u64::from(sector_size) as usize >> 5;

        let (sector_count, challenge_count) = match typ {
            PoStType::Winning => (winning::SECTORS_CHALLENGED, winning::CHALLENGE_COUNT),
            PoStType::Window => (
                window::sectors_challenged_per_partition(sector_nodes),
                window::CHALLENGE_COUNT_PER_SECTOR,
            ),
        };

        PoStConfig {
            sector_size,
            challenge_count,
            sector_count,
            typ,
            priority,
            api_version,
        }
    }

    pub fn padded_sector_size(&self) -> PaddedBytesAmount {
        PaddedBytesAmount::from(self.sector_size)
    }

    pub fn unpadded_sector_size(&self) -> UnpaddedBytesAmount {
        PaddedBytesAmount::from(self.sector_size).into()
    }

    /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
    pub fn get_cache_identifier<Tree>(&self) -> Result<String>
    where
        Tree: 'static + MerkleTreeTrait<Field = Fr>,
        Tree::Hasher: R1CSHasher,
    {
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

    pub fn get_cache_metadata_path<Tree>(&self) -> Result<PathBuf>
    where
        Tree: 'static + MerkleTreeTrait<Field = Fr>,
        Tree::Hasher: R1CSHasher,
    {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_metadata_path(&id))
    }

    pub fn get_cache_verifying_key_path<Tree>(&self) -> Result<PathBuf>
    where
        Tree: 'static + MerkleTreeTrait<Field = Fr>,
        Tree::Hasher: R1CSHasher,
    {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_verifying_key_path(&id))
    }

    pub fn get_cache_params_path<Tree>(&self) -> Result<PathBuf>
    where
        Tree: 'static + MerkleTreeTrait<Field = Fr>,
        Tree::Hasher: R1CSHasher,
    {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_params_path(&id))
    }
}
