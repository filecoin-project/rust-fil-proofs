use std::path::PathBuf;

use anyhow::Result;
use storage_proofs_core::{
    api_version::{ApiFeature, ApiVersion},
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
    POREP_PARTITIONS,
};

#[derive(Clone, Debug)]
pub struct PoRepConfig {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
    pub porep_id: [u8; 32],
    pub api_version: ApiVersion,
    pub api_features: Vec<ApiFeature>,
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
    /// construct PoRepConfig by groth16
    pub fn new_groth16(sector_size: u64, porep_id: [u8; 32], api_version: ApiVersion) -> Self {
        Self {
            sector_size: SectorSize(sector_size),
            partitions: PoRepProofPartitions(
                *POREP_PARTITIONS
                    .read()
                    .expect("POREP_PARTITIONS poisoned")
                    .get(&sector_size)
                    .expect("unknown sector size"),
            ),
            porep_id,
            api_version,
            api_features: vec![],
        }
    }

    #[inline]
    pub fn with_feature(mut self, feat: ApiFeature) -> Self {
        self.enable_feature(feat);
        self
    }

    #[inline]
    pub fn enable_feature(&mut self, feat: ApiFeature) {
        self.api_features.push(feat);
    }

    #[inline]
    pub fn padded_bytes_amount(&self) -> PaddedBytesAmount {
        PaddedBytesAmount::from(self.sector_size)
    }

    #[inline]
    pub fn unpadded_bytes_amount(&self) -> UnpaddedBytesAmount {
        self.padded_bytes_amount().into()
    }

    /// Returns the cache identifier as used by `storage-proofs::parameter_cache`.
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
