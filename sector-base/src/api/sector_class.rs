use crate::api::porep_config::PoRepConfig;
use crate::api::porep_proof_partitions::PoRepProofPartitions;
use crate::api::post_config::PoStConfig;
use crate::api::post_proof_partitions::PoStProofPartitions;
use crate::api::sector_size::SectorSize;

#[derive(Clone, Copy, Debug)]
pub enum SectorClass {
    Live(SectorSize, PoRepProofPartitions, PoStProofPartitions),
    Test,
}

impl From<SectorClass> for PoStConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass::Test => PoStConfig::Test,
            SectorClass::Live(ss, _, ppp) => PoStConfig::Live(ss, ppp),
        }
    }
}

impl From<SectorClass> for PoRepConfig {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass::Test => PoRepConfig::Test,
            SectorClass::Live(ss, ppp, _) => PoRepConfig::Live(ss, ppp),
        }
    }
}
