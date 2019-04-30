use crate::api::bytes_amount::PaddedBytesAmount;
use crate::api::bytes_amount::UnpaddedBytesAmount;
use crate::api::disk_backed_storage::LIVE_SECTOR_SIZE;
use crate::api::porep_proof_partitions::PoRepProofPartitions;
use crate::api::sector_size::SectorSize;

#[derive(Clone, Copy, Debug)]
pub struct PoRepConfig(pub SectorSize, pub PoRepProofPartitions);

impl Default for PoRepConfig {
    fn default() -> Self {
        PoRepConfig(SectorSize(LIVE_SECTOR_SIZE), PoRepProofPartitions(2))
    }
}

impl From<PoRepConfig> for PaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig(s, _) => PaddedBytesAmount::from(s),
        }
    }
}

impl From<PoRepConfig> for UnpaddedBytesAmount {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig(s, _) => PaddedBytesAmount::from(s).into(),
        }
    }
}

impl From<PoRepConfig> for PoRepProofPartitions {
    fn from(x: PoRepConfig) -> Self {
        match x {
            PoRepConfig(_, p) => p,
        }
    }
}
