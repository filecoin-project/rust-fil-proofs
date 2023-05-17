use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_update::constants::{h_default, partition_count};

use crate::types::{PoRepConfig, SectorSize, UpdateProofPartitions};

#[derive(Clone, Copy, Debug)]
pub struct SectorUpdateConfig {
    pub sector_size: SectorSize,
    pub nodes_count: usize,
    pub update_partitions: UpdateProofPartitions,
    pub h: usize,
}

impl SectorUpdateConfig {
    pub fn from_porep_config(porep_config: &PoRepConfig) -> Self {
        let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;

        SectorUpdateConfig {
            sector_size: porep_config.sector_size,
            nodes_count,
            update_partitions: UpdateProofPartitions::from(partition_count(nodes_count)),
            h: h_default(nodes_count),
        }
    }
}
