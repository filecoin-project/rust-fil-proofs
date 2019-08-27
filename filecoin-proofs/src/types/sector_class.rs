use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct SectorClass(pub SectorSize, pub PoRepProofPartitions);

impl From<SectorClass> for PoStConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass(ss, _) => PoStConfig(ss),
        }
    }
}

impl From<SectorClass> for PoRepConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass(ss, ppp) => PoRepConfig(ss, ppp),
        }
    }
}
