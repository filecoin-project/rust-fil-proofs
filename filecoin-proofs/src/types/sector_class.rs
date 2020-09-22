use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct SectorClass {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
    pub porep_id: [u8; 32],
    pub api_version: usize,
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
            api_version
        }
    }
}
