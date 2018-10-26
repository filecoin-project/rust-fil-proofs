#![cfg_attr(
    feature = "cargo-clippy",
    deny(all, clippy_perf, clippy_correctness)
)]
#![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal))]
#![cfg_attr(
    feature = "cargo-clippy",
    warn(type_complexity, too_many_arguments)
)]

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
extern crate env_logger;
extern crate pbr;
#[macro_use]
extern crate log;
extern crate colored;
extern crate rayon;

#[macro_use]
pub mod test_helper;

pub mod example_helper;

pub mod batchpost;
pub mod challenge_derivation;
pub mod circuit;
pub mod compound_proof;
pub mod crypto;
pub mod drgporep;
pub mod drgraph;
pub mod error;
pub mod file_inclusion_proof;
pub mod fr32;
pub mod hasher;
pub mod layered_drgporep;
pub mod merkle;
pub mod merklepor;
pub mod parameter_cache;
pub mod partitions;
pub mod porep;
pub mod proof;
pub mod util;
pub mod zigzag_drgporep;
pub mod zigzag_graph;

mod vde;
