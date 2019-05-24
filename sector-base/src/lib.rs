#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]

#[macro_use]
extern crate failure;

pub mod api;
pub mod error;
pub mod io;
