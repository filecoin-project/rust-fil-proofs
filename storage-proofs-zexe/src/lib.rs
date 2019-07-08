#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
extern crate bitvec;
#[cfg(test)]
#[macro_use]
extern crate proptest;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate slog;
#[macro_use]
extern crate serde;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[macro_use]
pub mod crypto;
pub mod drgraph;
pub mod error;
pub mod fr32;
pub mod hasher;
pub mod merkle;
pub mod parameter_cache;
pub mod partitions;
pub mod settings;
pub mod singletons;
pub mod util;
pub mod vde;
pub mod circuit;
pub mod compound_proof;
pub mod drgporep;
pub mod merklepor;
pub mod porep;
pub mod proof;

use logging_toolkit::make_logger;
use slog::Logger;

lazy_static! {
    pub static ref SP_LOG: Logger = make_logger("storage-proofs");
}
