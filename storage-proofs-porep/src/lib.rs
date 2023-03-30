#![deny(clippy::all, clippy::perf, clippy::correctness, rust_2018_idioms)]
#![warn(clippy::unwrap_used)]
#![cfg_attr(all(target_arch = "aarch64", nightly), feature(stdsimd))]
#![warn(clippy::unnecessary_wraps)]

pub mod stacked;

pub mod encode;

pub const MAX_LEGACY_POREP_REGISTERED_PROOF_ID: u64 = 4;
