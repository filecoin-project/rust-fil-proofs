use crate::api::bytes_amount::PaddedBytesAmount;
use crate::api::bytes_amount::UnpaddedBytesAmount;
use crate::io::fr32::unpadded_bytes;

#[derive(Clone, Copy, Debug)]
pub struct SectorSize(pub u64);

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
