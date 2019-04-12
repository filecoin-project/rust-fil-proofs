use crate::api::bytes_amount::PaddedBytesAmount;
use crate::api::bytes_amount::UnpaddedBytesAmount;
use crate::api::disk_backed_storage::LIVE_SECTOR_SIZE;
use crate::api::disk_backed_storage::TEST_SECTOR_SIZE;
use crate::io::fr32::unpadded_bytes;

#[derive(Clone, Copy, Debug)]
pub enum SectorSize {
    OneKiB,
    TwoHundredFiftySixMiB,
}

impl From<SectorSize> for UnpaddedBytesAmount {
    fn from(x: SectorSize) -> Self {
        match x {
            SectorSize::OneKiB => UnpaddedBytesAmount(unpadded_bytes(TEST_SECTOR_SIZE)),
            SectorSize::TwoHundredFiftySixMiB => {
                UnpaddedBytesAmount(unpadded_bytes(LIVE_SECTOR_SIZE))
            }
        }
    }
}

impl From<SectorSize> for PaddedBytesAmount {
    fn from(x: SectorSize) -> Self {
        match x {
            SectorSize::OneKiB => PaddedBytesAmount(TEST_SECTOR_SIZE),
            SectorSize::TwoHundredFiftySixMiB => PaddedBytesAmount(LIVE_SECTOR_SIZE),
        }
    }
}
