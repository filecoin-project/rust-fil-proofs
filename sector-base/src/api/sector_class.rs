use crate::api::porep_config::PoRepConfig;
use crate::api::porep_proof_partitions::PoRepProofPartitions;
use crate::api::post_config::PoStConfig;
use crate::api::post_proof_partitions::PoStProofPartitions;
use crate::api::sector_size::SectorSize;

#[derive(Clone, Copy, Debug)]
pub struct SectorClass(
    pub SectorSize,
    pub PoRepProofPartitions,
    pub PoStProofPartitions,
);

impl From<SectorClass> for PoStConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass(ss, _, ppp) => PoStConfig(ss, ppp),
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
