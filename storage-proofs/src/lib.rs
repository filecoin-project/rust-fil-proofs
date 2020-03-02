#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::type_repetition_in_bounds)]

#[macro_use]
pub mod test_helper;
pub mod example_helper;

pub mod cache_key;
pub mod compound_proof;
pub mod crypto;
pub mod drgraph;
pub mod error;
pub mod fr32;
pub mod hasher;
pub mod measurements;
pub mod merkle;
pub mod parameter_cache;
pub mod partitions;
pub mod pieces;
pub mod por;
pub mod porep;
pub mod post;
pub mod proof;
pub mod sector;
pub mod settings;
pub mod util;

pub mod gadgets;
pub mod multi_proof;

mod data;
mod encode;

pub use self::data::Data;

pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];
