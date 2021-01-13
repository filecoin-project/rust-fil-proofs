use storage_proofs_core::api_version::ApiVersion;

use crate::types::{PoRepConfig, PoRepProofPartitions, SectorSize};

#[derive(Clone, Copy, Debug)]
pub struct SectorClass {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
    pub porep_id: [u8; 32],
    pub api_version: ApiVersion,
}

impl From<SectorClass> for PoRepConfig {
    fn from(x: SectorClass) -> Self {
        let SectorClass {
            sector_size,
            partitions,
            porep_id,
            api_version,
        } = x;
        PoRepConfig {
            sector_size,
            partitions,
            porep_id,
            api_version,
        }
    }
}
