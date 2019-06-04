#![deny(clippy::all, clippy::perf, clippy::correctness)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;
#[macro_use]
extern crate slog;

mod caches;
mod constants;
mod file_cleanup;
mod post_adapter;
mod responses;
mod safe;
mod sector_builder;

pub mod error;
pub mod ffi_sector_builder;
pub mod ffi_stateless;
pub mod param;
pub mod parameters;
pub mod serde_big_array;
pub mod singletons;
