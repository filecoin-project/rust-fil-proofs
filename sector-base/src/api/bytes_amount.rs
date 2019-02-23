use serde::{Deserialize, Serialize};
use std::ops::{Add, Sub};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct UnpaddedBytesAmount(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PaddedBytesAmount(pub u64);

impl From<UnpaddedBytesAmount> for u64 {
    fn from(n: UnpaddedBytesAmount) -> Self {
        n.0
    }
}

impl From<UnpaddedBytesAmount> for usize {
    fn from(n: UnpaddedBytesAmount) -> Self {
        n.0 as usize
    }
}

impl From<PaddedBytesAmount> for u64 {
    fn from(n: PaddedBytesAmount) -> Self {
        n.0
    }
}

impl From<PaddedBytesAmount> for usize {
    fn from(n: PaddedBytesAmount) -> Self {
        n.0 as usize
    }
}

impl Add for UnpaddedBytesAmount {
    type Output = UnpaddedBytesAmount;

    fn add(self, other: UnpaddedBytesAmount) -> UnpaddedBytesAmount {
        UnpaddedBytesAmount(self.0 + other.0)
    }
}

impl Add for PaddedBytesAmount {
    type Output = PaddedBytesAmount;

    fn add(self, other: PaddedBytesAmount) -> PaddedBytesAmount {
        PaddedBytesAmount(self.0 + other.0)
    }
}

impl Sub for UnpaddedBytesAmount {
    type Output = UnpaddedBytesAmount;

    fn sub(self, other: UnpaddedBytesAmount) -> UnpaddedBytesAmount {
        UnpaddedBytesAmount(self.0 - other.0)
    }
}

impl Sub for PaddedBytesAmount {
    type Output = PaddedBytesAmount;

    fn sub(self, other: PaddedBytesAmount) -> PaddedBytesAmount {
        PaddedBytesAmount(self.0 - other.0)
    }
}
