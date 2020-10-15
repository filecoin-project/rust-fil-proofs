use std::path::PathBuf;

use anyhow::Result;
use storage_proofs_core::parameter_cache;

use crate::types::{PaddedBytesAmount, PoRepProofPartitions, SectorSize, UnpaddedBytesAmount};
use crate::with_shape_enum;

#[derive(Clone, Copy, Debug)]
pub struct PoRepConfig {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
    pub porep_id: [u8; 32],
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
    pub fn get_cache_identifier(&self) -> Result<String> {
        use storage_proofs_core::parameter_cache::CacheableParameters;
        use storage_proofs_porep::stacked::{StackedCircuit, StackedCompound};

        use crate::types::{DefaultPieceHasher, MerkleTreeTrait};

        fn inner<Tree: 'static + MerkleTreeTrait>(
            sector_size: SectorSize,
            partitions: usize,
            porep_id: [u8; 32],
        ) -> Result<String> {
            let params =
                crate::parameters::public_params::<Tree>(sector_size.into(), partitions, porep_id)?;

            let id = <StackedCompound<Tree, DefaultPieceHasher> as CacheableParameters<
                StackedCircuit<Tree, DefaultPieceHasher>,
                _,
            >>::cache_identifier(&params);
            Ok(id)
        }

        with_shape_enum!(
            self.sector_size,
            inner,
            self.sector_size,
            self.partitions.into(),
            self.porep_id
        )
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
