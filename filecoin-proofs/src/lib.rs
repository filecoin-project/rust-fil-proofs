#![deny(clippy::all, clippy::perf, clippy::correctness)]

//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

mod api;
mod caches;
mod commitment_reader;

pub mod constants;
pub mod fr32;
pub mod fr32_reader;
pub mod param;
pub mod parameters;
pub mod pieces;
pub mod serde_big_array;
pub mod types;

pub use self::api::*;
pub use self::commitment_reader::*;
pub use self::constants::SINGLE_PARTITION_PROOF_LEN;
pub use self::constants::*;
pub use self::types::*;

pub use storage_proofs;

#[cfg(test)]
pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];
