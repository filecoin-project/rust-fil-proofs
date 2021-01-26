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
use storage_proofs_porep::stacked::{StackedCircuit, StackedCompound};

use crate::{
    constants::DefaultPieceHasher,
    parameters::public_params,
    types::{PaddedBytesAmount, PoRepProofPartitions, SectorSize, UnpaddedBytesAmount},
};

#[derive(Clone, Copy, Debug)]
pub struct PoRepConfig {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
    pub porep_id: [u8; 32],
    pub api_version: ApiVersion,
}

impl From<PoRepConfig> for PaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        let PoRepConfig { sector_size, .. } = x;
        PaddedBytesAmount::from(sector_size)
    }
}

impl From<PoRepConfig> for UnpaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        let PoRepConfig { sector_size, .. } = x;
        PaddedBytesAmount::from(sector_size).into()
    }
}

impl From<PoRepConfig> for PoRepProofPartitions {
    fn from(x: PoRepConfig) -> Self {
        let PoRepConfig { partitions, .. } = x;
        partitions
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
    pub fn get_cache_identifier<Tree: 'static + MerkleTreeTrait>(&self) -> Result<String> {
        let params = public_params::<Tree>(
            self.sector_size.into(),
            self.partitions.into(),
            self.porep_id,
            self.api_version,
        )?;

        Ok(
            <StackedCompound<Tree, DefaultPieceHasher> as CacheableParameters<
                StackedCircuit<'_, Tree, DefaultPieceHasher>,
                _,
            >>::cache_identifier(&params),
        )
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
