use std::path::PathBuf;

use anyhow::Result;
use storage_proofs_core::parameter_cache::{self, CacheableParameters};
use storage_proofs_post::fallback;

use crate::types::{PaddedBytesAmount, SectorSize, UnpaddedBytesAmount};
use crate::with_shape_enum;

#[derive(Clone, Debug)]
pub struct PoStConfig {
    pub sector_size: SectorSize,
    pub challenge_count: usize,
    pub sector_count: usize,
    pub typ: PoStType,
    /// High priority (always runs on GPU) == true
    pub priority: bool,
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
    pub fn get_cache_identifier(&self) -> Result<String> {
        use crate::types::MerkleTreeTrait;

        pub fn inner<Tree: 'static + MerkleTreeTrait>(config: &PoStConfig) -> Result<String> {
            match config.typ {
                PoStType::Winning => {
                    let params = crate::parameters::winning_post_public_params::<Tree>(config)?;

                    Ok(
                        <fallback::FallbackPoStCompound<Tree> as CacheableParameters<
                            fallback::FallbackPoStCircuit<Tree>,
                            _,
                        >>::cache_identifier(&params),
                    )
                }
                PoStType::Window => {
                    let params = crate::parameters::window_post_public_params::<Tree>(config)?;

                    Ok(
                        <fallback::FallbackPoStCompound<Tree> as CacheableParameters<
                            fallback::FallbackPoStCircuit<Tree>,
                            _,
                        >>::cache_identifier(&params),
                    )
                }
            }
        }

        with_shape_enum!(self.sector_size, inner, self)
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
