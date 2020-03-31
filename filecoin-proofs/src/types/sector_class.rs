use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct SectorClass {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
}

impl From<SectorClass> for PoRepConfig {
    fn from(x: SectorClass) -> Self {
        let SectorClass {
            sector_size,
            partitions,
        } = x;
        PoRepConfig {
            sector_size,
            partitions,
        }
    }
}
