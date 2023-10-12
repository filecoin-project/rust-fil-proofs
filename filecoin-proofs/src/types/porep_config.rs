use std::path::PathBuf;

use anyhow::{anyhow, Result};
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
    constants::{self, DefaultPieceHasher},
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

    pub fn new_groth16_with_features(
        sector_size: u64,
        porep_id: [u8; 32],
        api_version: ApiVersion,
        api_features: Vec<ApiFeature>,
    ) -> Result<Self> {
        let mut config = Self {
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
        };
        for feature in api_features {
            config.enable_feature(feature)?;
        }
        Ok(config)
    }

    #[inline]
    pub fn enable_feature(&mut self, feat: ApiFeature) -> Result<()> {
        match feat {
            ApiFeature::SyntheticPoRep => {
                if self.feature_enabled(ApiFeature::NonInteractivePoRep) {
                    return Err(anyhow!(
                            "Cannot enable Synthetic PoRep when Non-interactive PoRep is already enabled"));
                }

                self.partitions = PoRepProofPartitions(
                    *POREP_PARTITIONS
                        .read()
                        .expect("POREP_PARTITIONS poisoned")
                        .get(&self.sector_size.into())
                        .expect("unknown sector size"),
                );
            }
            ApiFeature::NonInteractivePoRep => {
                if self.feature_enabled(ApiFeature::SyntheticPoRep) {
                    return Err(anyhow!(
                            "Cannot enable Non-interactive PoRep when Synthetic PoRep is already enabled"));
                }

                self.partitions = PoRepProofPartitions(
                    constants::get_porep_non_interactive_partitions(self.sector_size.into()),
                );
            }
        }

        if !self.feature_enabled(feat) {
            self.api_features.push(feat);
        }

        Ok(())
    }

    #[inline]
    pub fn feature_enabled(&self, feat: ApiFeature) -> bool {
        self.api_features.contains(&feat)
    }

    #[inline]
    pub fn padded_bytes_amount(&self) -> PaddedBytesAmount {
        PaddedBytesAmount::from(self.sector_size)
    }

    #[inline]
    pub fn unpadded_bytes_amount(&self) -> UnpaddedBytesAmount {
        self.padded_bytes_amount().into()
    }

    pub fn minimum_challenges(&self) -> usize {
        if self.feature_enabled(ApiFeature::NonInteractivePoRep) {
            constants::get_porep_non_interactive_minimum_challenges(u64::from(self.sector_size))
        } else {
            constants::get_porep_interactive_minimum_challenges(u64::from(self.sector_size))
        }
    }

    /// Returns the cache identifier as used by `storage-proofs::parameter_cache`.
    pub fn get_cache_identifier<Tree: 'static + MerkleTreeTrait>(&self) -> Result<String> {
        let params = public_params::<Tree>(self)?;

        Ok(
            <StackedCompound<Tree, DefaultPieceHasher> as CacheableParameters<
                StackedCircuit<Tree, DefaultPieceHasher>,
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
