use storage_proofs_core::util::NODE_SIZE;

use crate::types::{HSelect, SectorSize, UpdateProofPartitions};

#[derive(Clone, Copy, Debug)]
pub struct SectorUpdateConfig {
    pub sector_size: SectorSize,
    pub nodes_count: usize,
    pub update_partitions: UpdateProofPartitions,
    pub h_select: HSelect,
}

impl SectorUpdateConfig {
    pub fn from_sector_size<F: ff::PrimeField>(sector_size: SectorSize) -> Self {
        let nodes_count = u64::from(sector_size) as usize / NODE_SIZE;

        let partition_count = if storage_proofs_core::util::is_groth16_field::<F>() {
            storage_proofs_update::constants::partition_count(nodes_count)
        } else {
            storage_proofs_update::halo2::partition_count(nodes_count)
        };

        SectorUpdateConfig {
            sector_size,
            nodes_count,
            update_partitions: UpdateProofPartitions::from(partition_count),
            h_select: HSelect::from_nodes(nodes_count),
        }
    }
}
