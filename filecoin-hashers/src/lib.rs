#![deny(clippy::all, clippy::perf, clippy::correctness, rust_2018_idioms)]
#![allow(clippy::upper_case_acronyms)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::from_over_into)]
#![warn(clippy::wrong_self_convention)]

#[cfg(feature = "blake2s")]
pub mod blake2s;
#[cfg(feature = "poseidon")]
pub mod poseidon;
#[cfg(feature = "poseidon")]
mod poseidon_types;
#[cfg(feature = "sha256")]
pub mod sha256;

mod types;

pub use self::types::*;
