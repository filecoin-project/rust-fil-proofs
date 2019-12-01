use std::path::PathBuf;

use anyhow::Result;

use paired::bls12_381::Bls12;
use storage_proofs::circuit::stacked::{StackedCircuit, StackedCompound};
use storage_proofs::drgraph::DefaultTreeHasher;
use storage_proofs::parameter_cache::{self, CacheableParameters};

use crate::constants::DefaultPieceHasher;
use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct PoRepConfig {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
}

impl From<PoRepConfig> for PaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig { sector_size, .. } => PaddedBytesAmount::from(sector_size),
        }
    }
}

impl From<PoRepConfig> for UnpaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig { sector_size, .. } => PaddedBytesAmount::from(sector_size).into(),
        }
    }
}

impl From<PoRepConfig> for PoRepProofPartitions {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig { partitions, .. } => partitions,
        }
    }
}

impl From<PoRepConfig> for SectorSize {
    fn from(cfg: PoRepConfig) -> Self {
        let PoRepConfig { sector_size, .. } = cfg;
        sector_size
    }
}

impl PoRepConfig {
    /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
    pub fn get_cache_identifier(&self) -> Result<String> {
        let params =
            crate::parameters::public_params(self.sector_size.into(), self.partitions.into())?;

        Ok(<StackedCompound as CacheableParameters<
            Bls12,
            StackedCircuit<_, DefaultTreeHasher, DefaultPieceHasher>,
            _,
        >>::cache_identifier(&params))
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
