#![cfg_attr(
    feature = "cargo-clippy",
    deny(clippy::all, clippy::perf, clippy::correctness)
)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![cfg_attr(
    feature = "cargo-clippy",
    warn(clippy::type_complexity, clippy::too_many_arguments)
)]

extern crate ffi_toolkit;
extern crate sector_base;
extern crate storage_proofs;

#[macro_use]
extern crate lazy_static;
extern crate bellman;
extern crate libc;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;
extern crate tempfile;
#[macro_use]
extern crate failure;
extern crate byteorder;
extern crate itertools;
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate serde_derive;
extern crate blake2;

pub mod api;
pub mod error;
pub mod serde_big_array;
