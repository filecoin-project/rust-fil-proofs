#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate serde;
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
