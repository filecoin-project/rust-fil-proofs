//! ZigZag Proof-of-Replication.
//!
//! This is a re-implementation of the historical ZigZag layered PoRep (removed in 2019 when it was
//! replaced by Stacked DRG), ported to the current codebase. It lives alongside `stacked` and
//! reuses the modern hasher, graph, and Merkle-tree abstractions.
//!
//! The 2019 reference sources this is ported from are preserved (uncompiled) under
//! `zigzag-reference/` at the repository root.

pub mod circuit;
pub(crate) mod vanilla;

pub use vanilla::*;
