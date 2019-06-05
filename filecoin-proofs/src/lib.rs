#![deny(clippy::all, clippy::perf, clippy::correctness)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate slog;

mod api;
mod caches;
mod file_cleanup;

pub mod constants;
pub mod error;
pub mod fr32;
pub mod param;
pub mod parameters;
pub mod post_adapter;
pub mod serde_big_array;
pub mod singletons;
pub mod types;

pub use api::*;
