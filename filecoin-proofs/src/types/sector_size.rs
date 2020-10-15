use std::convert::TryFrom;
use std::ops::Deref;

use crate::constants;
use crate::types::{PaddedBytesAmount, UnpaddedBytesAmount};

use anyhow::Result;
use fr32::to_unpadded_bytes;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SectorSize {
    KiB2,
    KiB4,
    KiB16,
    KiB32,
    MiB8,
    MiB16,
    MiB512,
    GiB1,
    GiB32,
    GiB64,
    #[cfg(test)]
    Arbitrary(u64),
}

impl Deref for SectorSize {
    type Target = u64;

    fn deref(&self) -> &Self::Target {
        match *self {
            SectorSize::KiB2 => &constants::SECTOR_SIZE_2_KIB,
            SectorSize::KiB4 => &constants::SECTOR_SIZE_4_KIB,
            SectorSize::KiB16 => &constants::SECTOR_SIZE_16_KIB,
            SectorSize::KiB32 => &constants::SECTOR_SIZE_32_KIB,
            SectorSize::MiB8 => &constants::SECTOR_SIZE_8_MIB,
            SectorSize::MiB16 => &constants::SECTOR_SIZE_16_MIB,
            SectorSize::MiB512 => &constants::SECTOR_SIZE_512_MIB,
            SectorSize::GiB1 => &constants::SECTOR_SIZE_1_GIB,
            SectorSize::GiB32 => &constants::SECTOR_SIZE_32_GIB,
            SectorSize::GiB64 => &constants::SECTOR_SIZE_64_GIB,
            #[cfg(test)]
            SectorSize::Arbitrary(ref v) => v,
        }
    }
}

impl From<SectorSize> for u64 {
    fn from(size: SectorSize) -> Self {
        **&size
    }
}

impl From<SectorSize> for usize {
    fn from(size: SectorSize) -> Self {
        **&size as usize
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid SectorSize")]
pub struct InvalidSectorSize;

impl TryFrom<u64> for SectorSize {
    type Error = InvalidSectorSize;

    fn try_from(size: u64) -> Result<Self, Self::Error> {
        match size {
            _x if size == constants::SECTOR_SIZE_2_KIB => Ok(SectorSize::KiB2),
            _x if size == constants::SECTOR_SIZE_4_KIB => Ok(SectorSize::KiB4),
            _x if size == constants::SECTOR_SIZE_16_KIB => Ok(SectorSize::KiB16),
            _x if size == constants::SECTOR_SIZE_32_KIB => Ok(SectorSize::KiB32),
            _x if size == constants::SECTOR_SIZE_8_MIB => Ok(SectorSize::MiB8),
            _x if size == constants::SECTOR_SIZE_16_MIB => Ok(SectorSize::MiB16),
            _x if size == constants::SECTOR_SIZE_512_MIB => Ok(SectorSize::MiB512),
            _x if size == constants::SECTOR_SIZE_1_GIB => Ok(SectorSize::GiB1),
            _x if size == constants::SECTOR_SIZE_32_GIB => Ok(SectorSize::GiB32),
            _x if size == constants::SECTOR_SIZE_64_GIB => Ok(SectorSize::GiB64),
            _ => Err(InvalidSectorSize),
        }
    }
}

impl From<SectorSize> for UnpaddedBytesAmount {
    fn from(x: SectorSize) -> Self {
        UnpaddedBytesAmount(to_unpadded_bytes(x.into()))
    }
}

impl From<SectorSize> for PaddedBytesAmount {
    fn from(x: SectorSize) -> Self {
        PaddedBytesAmount(x.into())
    }
}
