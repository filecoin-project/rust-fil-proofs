#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::type_repetition_in_bounds)]

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
#[macro_use]
extern crate proptest;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[macro_use]
pub mod test_helper;

pub mod example_helper;

pub mod circuit;
pub mod compound_proof;
pub mod crypto;
pub mod drgporep;
pub mod drgraph;
pub mod election_post;
mod encode;
pub mod error;
pub mod fr32;
pub mod hasher;
pub mod merkle;
pub mod merklepor;
pub mod parameter_cache;
pub mod partitions;
pub mod pieces;
pub mod porep;
pub mod proof;
pub mod rational_post;
pub mod sector;
pub mod settings;
pub mod stacked;
pub mod util;

pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];
