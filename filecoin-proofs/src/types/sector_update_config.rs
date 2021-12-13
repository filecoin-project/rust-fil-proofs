use storage_proofs_core::util::NODE_SIZE;
use storage_proofs_update::constants::partition_count;

use crate::types::{HSelect, PoRepConfig, SectorSize, UpdateProofPartitions};

#[derive(Clone, Copy, Debug)]
pub struct SectorUpdateConfig {
    pub sector_size: SectorSize,
    pub nodes_count: usize,
    pub update_partitions: UpdateProofPartitions,
    pub h_select: HSelect,
}

impl SectorUpdateConfig {
    pub fn from_porep_config(porep_config: PoRepConfig) -> Self {
        let nodes_count = u64::from(porep_config.sector_size) as usize / NODE_SIZE;

        SectorUpdateConfig {
            sector_size: porep_config.sector_size,
            nodes_count,
            update_partitions: UpdateProofPartitions::from(partition_count(nodes_count)),
            h_select: HSelect::from_nodes(nodes_count),
        }
    }
}
