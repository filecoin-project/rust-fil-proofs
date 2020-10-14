#![deny(clippy::all, clippy::perf, clippy::correctness)]

//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

pub(crate) mod util;

pub mod cache;
pub mod commitments;
pub mod constants;
pub mod parameters;
pub mod pieces;
pub mod post;
pub mod seal;
pub mod types;
pub mod unseal;

#[cfg(test)]
pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];
