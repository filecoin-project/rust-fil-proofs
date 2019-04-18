use crate::api::bytes_amount::PaddedBytesAmount;
use crate::api::bytes_amount::UnpaddedBytesAmount;
use crate::api::disk_backed_storage::TEST_SECTOR_SIZE;
use crate::api::post_proof_partitions::PoStProofPartitions;
use crate::api::sector_size::SectorSize;

#[derive(Clone, Copy, Debug)]
pub enum PoStConfig {
    Live(SectorSize, PoStProofPartitions),
    Test,
}

impl Default for PoStConfig {
    fn default() -> Self {
        PoStConfig::Live(SectorSize::TwoHundredFiftySixMiB, PoStProofPartitions::One)
    }
}

impl From<PoStConfig> for PaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig::Test => PaddedBytesAmount(TEST_SECTOR_SIZE),
            PoStConfig::Live(s, _) => PaddedBytesAmount::from(s),
        }
    }
}

impl From<PoStConfig> for UnpaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig::Test => PaddedBytesAmount(TEST_SECTOR_SIZE).into(),
            PoStConfig::Live(s, _) => PaddedBytesAmount::from(s).into(),
        }
    }
}

impl From<PoStConfig> for PoStProofPartitions {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig::Test => PoStProofPartitions::One,
            PoStConfig::Live(_, p) => p,
        }
    }
}
