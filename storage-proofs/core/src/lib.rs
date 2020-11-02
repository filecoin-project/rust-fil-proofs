#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::type_repetition_in_bounds)]
//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

#[macro_use]
pub mod test_helper;

pub mod cache_key;
pub mod compound_proof;
pub mod crypto;
pub mod data;
pub mod drgraph;
pub mod error;
pub mod fr32;
pub mod gadgets;
pub mod hasher;
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
pub mod util;

pub use self::data::Data;

#[cfg(test)]
pub(crate) const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];

pub const MAX_LEGACY_POREP_REGISTERED_PROOF_ID: u64 = 4;

pub type PoRepID = [u8; 32];
pub fn is_legacy_porep_id(porep_id: PoRepID) -> bool {
    use std::convert::TryInto;

    // NOTE: Because we take only the first 8 bytes, we are actually examining the registered proof type id,
    // not the porep_id. The latter requires the full 32 bytes and includes the nonce.
    // We are, to some extent depending explictly on the strucuture of the `porep_id`.
    // Of course, it happens to be the case that only the 'legacy' ids in question can ever satisfy
    // this predicate, so the distinction is somewhat moot. However, for the sake of clarity in any future
    // use of `porep_id`, we should pay close attention to this.
    let id = u64::from_le_bytes(porep_id[..8].try_into().unwrap());
    id <= MAX_LEGACY_POREP_REGISTERED_PROOF_ID
}
