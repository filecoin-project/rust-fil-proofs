#![deny(clippy::all, clippy::perf, clippy::correctness, rust_2018_idioms)]
#![warn(clippy::unwrap_used)]

pub mod election;
pub mod fallback;
#[cfg(feature = "halo2")]
pub mod halo2;
#[cfg(feature = "nova")]
pub mod nova;
pub mod rational;
