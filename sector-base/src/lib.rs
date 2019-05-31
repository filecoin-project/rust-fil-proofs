#![deny(clippy::all, clippy::perf, clippy::correctness)]

#[macro_use]
extern crate failure;

pub mod api;
pub mod error;
pub mod io;
