#![cfg_attr(
    feature = "cargo-clippy",
    deny(all, clippy_perf, clippy_correctness)
)]
#![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal))]
#![cfg_attr(
    feature = "cargo-clippy",
    warn(type_complexity, too_many_arguments)
)]

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
