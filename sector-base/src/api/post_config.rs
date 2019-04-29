use crate::api::bytes_amount::PaddedBytesAmount;
use crate::api::bytes_amount::UnpaddedBytesAmount;
use crate::api::disk_backed_storage::LIVE_SECTOR_SIZE;
use crate::api::post_proof_partitions::PoStProofPartitions;
use crate::api::sector_size::SectorSize;

#[derive(Clone, Copy, Debug)]
pub struct PoStConfig(pub SectorSize, pub PoStProofPartitions);

impl Default for PoStConfig {
    fn default() -> Self {
        PoStConfig(SectorSize(LIVE_SECTOR_SIZE), PoStProofPartitions::One)
    }
}

impl From<PoStConfig> for PaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(s, _) => PaddedBytesAmount::from(s),
        }
    }
}

impl From<PoStConfig> for UnpaddedBytesAmount {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(s, _) => PaddedBytesAmount::from(s).into(),
        }
    }
}

impl From<PoStConfig> for PoStProofPartitions {
    fn from(x: PoStConfig) -> Self {
        match x {
            PoStConfig(_, p) => p,
        }
    }
}
