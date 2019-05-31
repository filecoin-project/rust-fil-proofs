#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
#[macro_use]
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
pub mod test_helper;

pub mod example_helper;

pub mod batchpost;
pub mod beacon_post;
pub mod challenge_derivation;
pub mod circuit;
pub mod compound_proof;
pub mod crypto;
pub mod drgporep;
pub mod drgraph;
pub mod error;
pub mod fr32;
pub mod hasher;
pub mod layered_drgporep;
pub mod merkle;
pub mod merklepor;
pub mod parameter_cache;
pub mod partitions;
pub mod piece_inclusion_proof;
pub mod porc;
pub mod porep;
pub mod proof;
pub mod settings;
pub mod util;
pub mod vdf;
pub mod vdf_post;
pub mod vdf_sloth;
pub mod zigzag_drgporep;
pub mod zigzag_graph;

pub mod vde;

use logging_toolkit::make_logger;
use slog::Logger;

lazy_static! {
    pub static ref SP_LOG: Logger = make_logger("storage-proofs");
}
