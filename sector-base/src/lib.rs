#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]
#![warn(clippy::type_complexity, clippy::too_many_arguments)]

extern crate bitvec;
#[macro_use]
extern crate failure;
extern crate ffi_toolkit;
extern crate itertools;
extern crate libc;
extern crate pairing;
extern crate rand;
extern crate storage_proofs;

#[cfg(test)]
extern crate tempfile;

pub mod api;
pub mod error;
pub mod io;
