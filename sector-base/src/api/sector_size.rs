use crate::api::bytes_amount::PaddedBytesAmount;
use crate::api::bytes_amount::UnpaddedBytesAmount;
use crate::api::disk_backed_storage::LIVE_SECTOR_SIZE;
use crate::api::disk_backed_storage::TEST_SECTOR_SIZE;
use crate::io::fr32::unpadded_bytes;

#[derive(Clone, Copy, Debug)]
pub struct SectorSize(pub u64);

pub const SECTOR_SIZE_CHOICES: [SectorSize; 2] =
    [SectorSize(TEST_SECTOR_SIZE), SectorSize(LIVE_SECTOR_SIZE)];

impl From<SectorSize> for UnpaddedBytesAmount {
    fn from(x: SectorSize) -> Self {
        UnpaddedBytesAmount(unpadded_bytes(x.0))
    }
}

impl From<SectorSize> for PaddedBytesAmount {
    fn from(x: SectorSize) -> Self {
        PaddedBytesAmount(x.0)
    }
}
