use std::path::PathBuf;

use anyhow::Result;
use blstrs::Scalar as Fr;
use filecoin_hashers::Groth16Hasher;
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
    POREP_PARTITIONS,
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
    /// construct PoRepConfig by halo2
    pub fn new_halo2(sector_size: SectorSize, porep_id: [u8; 32], api_version: ApiVersion) -> Self {
        let sector_nodes = u64::from(sector_size) as usize >> 5;
        let partitions = storage_proofs_porep::stacked::halo2::partition_count(sector_nodes);
        PoRepConfig {
            sector_size,
            partitions: PoRepProofPartitions::from(partitions),
            porep_id,
            api_version,
        }
    }

    /// construct PoRepConfig by groth16
    pub fn new_groth16(sector_size: u64, porep_id: [u8; 32], api_version: ApiVersion) -> Self {
        Self {
            sector_size: SectorSize(sector_size),
            partitions: PoRepProofPartitions(
                *POREP_PARTITIONS
                    .read()
                    .expect("POREP_PARTITIONS poisoned")
                    .get(&sector_size)
                    .expect("unknown sector size") as usize,
            ),
            porep_id,
            api_version,
        }
    }

    /// Returns the cache identifier as used by `storage-proofs::parameter_cache`.
    pub fn get_cache_identifier<Tree>(&self) -> Result<String>
    where
        Tree: 'static + MerkleTreeTrait<Field = Fr>,
        Tree::Hasher: Groth16Hasher,
    {
        let params = public_params::<Tree>(
            self.sector_size.into(),
            self.partitions.into(),
            self.porep_id,
            self.api_version,
        )?;

        Ok(
            <StackedCompound<Tree, DefaultPieceHasher<Fr>> as CacheableParameters<
                StackedCircuit<'_, Tree, DefaultPieceHasher<Fr>>,
                _,
            >>::cache_identifier(&params),
        )
    }

    pub fn get_cache_metadata_path<Tree>(&self) -> Result<PathBuf>
    where
        Tree: 'static + MerkleTreeTrait<Field = Fr>,
        Tree::Hasher: Groth16Hasher,
    {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_metadata_path(&id))
    }

    pub fn get_cache_verifying_key_path<Tree>(&self) -> Result<PathBuf>
    where
        Tree: 'static + MerkleTreeTrait<Field = Fr>,
        Tree::Hasher: Groth16Hasher,
    {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_verifying_key_path(&id))
    }

    pub fn get_cache_params_path<Tree>(&self) -> Result<PathBuf>
    where
        Tree: 'static + MerkleTreeTrait<Field = Fr>,
        Tree::Hasher: Groth16Hasher,
    {
        let id = self.get_cache_identifier::<Tree>()?;
        Ok(parameter_cache_params_path(&id))
    }
}
