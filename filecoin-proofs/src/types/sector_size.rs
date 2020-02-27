use crate::fr32::unpadded_bytes;
use crate::types::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

impl From<SectorSize> for u64 {
    fn from(x: SectorSize) -> Self {
        x.0
    }
}
