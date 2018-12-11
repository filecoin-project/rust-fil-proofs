#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]
#![warn(clippy::type_complexity, clippy::too_many_arguments)]

extern crate ffi_toolkit;
extern crate logging_toolkit;
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
extern crate slog;

pub mod api;
pub mod error;
pub mod serde_big_array;

use logging_toolkit::make_logger;
use slog::Logger;

lazy_static! {
    pub static ref FCP_LOG: Logger = make_logger(
        "filecoin-proofs",
        "RUST_PROOFS_LOG_JSON",
        "RUST_PROOFS_MIN_LOG_LEVEL"
    );
}
