use std::path::PathBuf;

use paired::bls12_381::Bls12;
use storage_proofs::circuit::stacked::{StackedCircuit, StackedCompound};
use storage_proofs::drgraph::DefaultTreeHasher;
use storage_proofs::parameter_cache::{self, CacheableParameters};

use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct PoRepConfig(pub SectorSize, pub PoRepProofPartitions);

impl From<PoRepConfig> for PaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig(s, _) => PaddedBytesAmount::from(s),
        }
    }
}

impl From<PoRepConfig> for UnpaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig(s, _) => PaddedBytesAmount::from(s).into(),
        }
    }
}

impl From<PoRepConfig> for PoRepProofPartitions {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig(_, p) => p,
        }
    }
}

impl PoRepConfig {
    /// Returns the cache identifier as used by `storage-proofs::paramater_cache`.
    pub fn get_cache_identifier(&self) -> String {
        let params = crate::parameters::public_params(self.0.into(), self.1.into());

        <StackedCompound as CacheableParameters<Bls12, StackedCircuit<_, DefaultTreeHasher>, _>>::cache_identifier(
            &params,
        )
    }

    pub fn get_cache_metadata_path(&self) -> PathBuf {
        let id = self.get_cache_identifier();
        parameter_cache::parameter_cache_metadata_path(&id)
    }

    pub fn get_cache_verifying_key_path(&self) -> PathBuf {
        let id = self.get_cache_identifier();
        parameter_cache::parameter_cache_verifying_key_path(&id)
    }

    pub fn get_cache_params_path(&self) -> PathBuf {
        let id = self.get_cache_identifier();
        parameter_cache::parameter_cache_params_path(&id)
    }
}
