#![deny(clippy::all, clippy::perf, clippy::correctness)]

// These need to be here because of cbindgen: https://github.com/eqrion/cbindgen/issues/292
extern crate filecoin_proofs;
extern crate sector_builder;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate failure;

mod error;
mod responses;
mod singletons;

pub mod builder;
pub mod stateless;
