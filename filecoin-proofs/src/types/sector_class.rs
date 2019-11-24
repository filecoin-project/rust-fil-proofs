use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct SectorClass {
    pub sector_size: SectorSize,
    pub partitions: PoRepProofPartitions,
    pub window_size_nodes: usize,
}

impl From<SectorClass> for PoStConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass {
                sector_size,
                window_size_nodes,
                ..
            } => PoStConfig {
                sector_size,
                window_size_nodes,
            },
        }
    }
}

impl From<SectorClass> for PoRepConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass {
                sector_size,
                partitions,
                window_size_nodes,
            } => PoRepConfig {
                sector_size,
                partitions,
                window_size_nodes,
            },
        }
    }
}
