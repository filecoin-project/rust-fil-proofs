#![deny(clippy::all, clippy::perf, clippy::correctness, rust_2018_idioms)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::type_repetition_in_bounds)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::redundant_slicing)]
#![allow(clippy::unnecessary_wraps)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::ptr_arg)]
#![warn(clippy::unnecessary_lazy_evaluations)]

use std::convert::TryInto;

pub mod api_version;
pub mod cache_key;
pub mod compound_proof;
pub mod crypto;
pub mod data;
pub mod drgraph;
pub mod error;
pub mod gadgets;
pub mod halo2;
pub mod measurements;
pub mod merkle;
pub mod multi_proof;
pub mod parameter_cache;
pub mod partitions;
pub mod pieces;
pub mod por;
pub mod proof;
pub mod sector;
pub mod settings;
pub mod test_helper;
pub mod util;

pub use data::Data;

pub const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];

pub const MAX_LEGACY_POREP_REGISTERED_PROOF_ID: u64 = 4;

// Sector sizes measured in nodes.
pub const SECTOR_NODES_1_KIB: usize = 1 << 5;
pub const SECTOR_NODES_2_KIB: usize = 1 << 6;
pub const SECTOR_NODES_4_KIB: usize = 1 << 7;
pub const SECTOR_NODES_8_KIB: usize = 1 << 8;
pub const SECTOR_NODES_16_KIB: usize = 1 << 9;
pub const SECTOR_NODES_32_KIB: usize = 1 << 10;
pub const SECTOR_NODES_8_MIB: usize = 1 << 18;
pub const SECTOR_NODES_16_MIB: usize = 1 << 19;
pub const SECTOR_NODES_512_MIB: usize = 1 << 24;
pub const SECTOR_NODES_1_GIB: usize = 1 << 25;
pub const SECTOR_NODES_32_GIB: usize = 1 << 30;
pub const SECTOR_NODES_64_GIB: usize = 1 << 31;

pub type PoRepID = [u8; 32];

pub fn is_legacy_porep_id(porep_id: PoRepID) -> bool {
    // NOTE: Because we take only the first 8 bytes, we are actually examining the registered proof type id,
    // not the porep_id. The latter requires the full 32 bytes and includes the nonce.
    // We are, to some extent depending explictly on the strucuture of the `porep_id`.
    // Of course, it happens to be the case that only the 'legacy' ids in question can ever satisfy
    // this predicate, so the distinction is somewhat moot. However, for the sake of clarity in any future
    // use of `porep_id`, we should pay close attention to this.
    let id = u64::from_le_bytes(
        porep_id[..8]
            .try_into()
            .expect("8 bytes is always a valid u64"),
    );
    id <= MAX_LEGACY_POREP_REGISTERED_PROOF_ID
}
