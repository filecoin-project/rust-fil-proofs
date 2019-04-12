use crate::api::bytes_amount::PaddedBytesAmount;
use crate::api::bytes_amount::UnpaddedBytesAmount;
use crate::api::disk_backed_storage::TEST_SECTOR_SIZE;
use crate::api::sector_size::SectorSize;

#[derive(Clone, Copy, Debug)]
pub enum PoRepConfig {
    Live(SectorSize, PoRepProofPartitions),
    Test,
}

#[derive(Clone, Copy, Debug)]
pub enum PoRepProofPartitions {
    Two,
}

impl Default for PoRepConfig {
    fn default() -> Self {
        PoRepConfig::Live(SectorSize::TwoHundredFiftySixMiB, PoRepProofPartitions::Two)
    }
}

impl From<PoRepConfig> for PaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig::Test => PaddedBytesAmount(TEST_SECTOR_SIZE),
            PoRepConfig::Live(s, _) => PaddedBytesAmount::from(s),
        }
    }
}

impl From<PoRepConfig> for UnpaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig::Test => PaddedBytesAmount(TEST_SECTOR_SIZE).into(),
            PoRepConfig::Live(s, _) => PaddedBytesAmount::from(s).into(),
        }
    }
}

impl From<PoRepConfig> for PoRepProofPartitions {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig::Test => PoRepProofPartitions::Two,
            PoRepConfig::Live(_, p) => p,
        }
    }
}

impl From<PoRepProofPartitions> for usize {
    fn from(x: PoRepProofPartitions) -> Self {
        match x {
            PoRepProofPartitions::Two => 2,
        }
    }
}
