#![deny(clippy::all, clippy::perf, clippy::correctness)]

mod padding_map;
mod reader;
mod types;

pub use self::types::*;
pub use padding_map::*;
pub use reader::*;

#[cfg(test)]
pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];
