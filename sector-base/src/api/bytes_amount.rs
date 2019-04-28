use crate::io::fr32::padded_bytes;
use crate::io::fr32::unpadded_bytes;
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

// //Delete the implementation for usize, since it could bring potential issue on a 32-bit system
// // to fix #622
// impl From<UnpaddedBytesAmount> for usize {
//     fn from(n: UnpaddedBytesAmount) -> Self {
//         n.0 as usize
//     }
// }

// This could potentially trigger some issues, when convert u64 to usize and reverse back.
// Todo: need to find where this function is called and what's the impact
impl From<UnpaddedBytesAmount> for PaddedBytesAmount {
    fn from(n: UnpaddedBytesAmount) -> Self {
        PaddedBytesAmount(padded_bytes(n.0 as usize) as u64)
    }
}

impl From<PaddedBytesAmount> for u64 {
    fn from(n: PaddedBytesAmount) -> Self {
        n.0
    }
}

// //Delete the implementation for usize, to fix issue #622
// impl From<PaddedBytesAmount> for usize {
//     fn from(n: PaddedBytesAmount) -> Self {
//         n.0 as usize
//     }
// }

impl From<PaddedBytesAmount> for UnpaddedBytesAmount {
    fn from(n: PaddedBytesAmount) -> Self {
        UnpaddedBytesAmount(unpadded_bytes(n.0))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_operations() {
        let a = UnpaddedBytesAmount(1);
        let b = UnpaddedBytesAmount(2);
        let c = UnpaddedBytesAmount(3);

        let d = PaddedBytesAmount(1);
        let e = PaddedBytesAmount(2);
        let f = PaddedBytesAmount(3);

        // Operations between UnpaddedBytesAmounts are allowed
        assert_eq!(a + b, c);
        assert_eq!(c - b, a);

        // Operations between PaddedBytesAmounts are allowed
        assert_eq!(d + e, f);
        assert_eq!(f - e, d);

        // Mixed operations fail at compile time.
        // assert_eq!(a + b, f);

        // Coercion to primitives work
        assert_eq!(1u64 + u64::from(b), 3u64);
        assert_eq!(1usize + usize::from(b), 3usize);
        assert_eq!(1u64 + u64::from(e), 3u64);
        assert_eq!(1usize + usize::from(e), 3usize);

        // But not between BytesAmount types
        // assert_eq!(a + UnpaddedBytesAmount::from(e), c);
        // assert_eq!(d + UnpaddedBytesAmount::from(b), f);

        // But must be explicit or won't compile.
        // assert_eq!(1u64 + b, 3u64);
        // assert_eq!(1usize + b, 3usize);
        // assert_eq!(1u64 + u64::from(e), 3u64);
        // assert_eq!(1usize + usize::from(e), 3usize);
    }
}