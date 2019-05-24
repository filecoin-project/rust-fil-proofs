#![deny(clippy::all, clippy::perf, clippy::correctness)]

extern crate ffi_toolkit;
extern crate logging_toolkit;
extern crate sector_base;
extern crate storage_proofs;

#[macro_use]
extern crate lazy_static;
extern crate bellperson;
extern crate fil_sapling_crypto;
extern crate libc;
extern crate paired;
extern crate rand;
extern crate tempfile;
#[macro_use]
extern crate failure;
extern crate byteorder;
extern crate itertools;
#[macro_use]
extern crate serde;
extern crate serde_cbor;
#[macro_use]
extern crate slog;

pub mod api;
pub mod error;
pub mod param;
pub mod serde_big_array;

use logging_toolkit::make_logger;
use slog::Logger;

lazy_static! {
    pub static ref FCP_LOG: Logger = make_logger("filecoin-proofs");
}
