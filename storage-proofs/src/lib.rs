#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]

extern crate logging_toolkit;

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate aes;
extern crate bellman;
#[cfg(test)]
#[macro_use]
extern crate bitvec;
#[cfg(not(test))]
extern crate bitvec;
extern crate blake2;
extern crate block_modes;
extern crate byteorder;
extern crate crossbeam_utils;
extern crate fs2;
extern crate itertools;
extern crate libc;
extern crate memmap;
extern crate merkle_light;
extern crate num_bigint;
extern crate num_traits;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate sha2;
extern crate tempfile;
#[cfg(test)]
#[macro_use]
extern crate proptest;
#[macro_use]
extern crate clap;
extern crate colored;
extern crate pbr;
extern crate rayon;
#[macro_use]
extern crate slog;
#[macro_use]
extern crate serde;
extern crate toml;

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
pub mod config;
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
