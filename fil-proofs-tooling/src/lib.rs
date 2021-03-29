#![deny(clippy::all, clippy::perf, clippy::correctness, rust_2018_idioms)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::needless_collect)]

pub mod measure;
pub mod metadata;
pub mod shared;
pub use measure::{measure, FuncMeasurement};
pub use metadata::Metadata;
pub use shared::{create_replica, create_replicas};
