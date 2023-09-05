#![deny(clippy::all, clippy::perf, clippy::correctness, rust_2018_idioms)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::unnecessary_wraps)]
#![allow(clippy::upper_case_acronyms)]

#[cfg(all(feature = "cuda", feature = "cuda-supraseal"))]
compile_error!(
    "The `cuda` and `cuda-supraseal` cannot be enabled at the same time, choose one of them."
);

pub mod caches;
pub mod chunk_iter;
pub mod constants;
pub mod param;
pub mod parameters;
pub mod pieces;
pub mod types;

mod api;
mod commitment_reader;

pub use api::*;
pub use chunk_iter::ChunkIterator;
pub use commitment_reader::*;
pub use constants::*;
pub use types::*;
