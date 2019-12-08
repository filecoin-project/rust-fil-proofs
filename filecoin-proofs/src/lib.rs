#![deny(clippy::all, clippy::perf, clippy::correctness)]

mod api;
mod caches;

pub mod constants;
pub mod fr32;
pub mod param;
pub mod parameters;
pub mod pieces;
pub mod serde_big_array;
pub mod singletons;
pub mod types;

pub use api::*;
pub use constants::SINGLE_PARTITION_PROOF_LEN;
pub use types::*;

#[cfg(test)]
pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];
