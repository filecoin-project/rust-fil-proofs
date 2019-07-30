use crate::types::*;

#[derive(Clone, Copy, Debug)]
pub struct SectorClass(
    pub SectorSize,
    pub PoRepProofPartitions,
    pub PoStProofPartitions,
);

impl From<SectorClass> for PoStConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass(ss, _, _) => PoStConfig(ss),
        }
    }
}

impl From<SectorClass> for PoRepConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass(ss, ppp, _) => PoRepConfig(ss, ppp),
        }
    }
}
