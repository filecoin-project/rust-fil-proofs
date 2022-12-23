#![allow(clippy::len_without_is_empty)]

use std::fs::File;

pub use merkletree::store::{DiskStore, ExternalReader, Store};

use filecoin_hashers::Hasher;
use generic_array::typenum::{U0, U2};
use merkletree::store::LevelCacheStore;

mod builders;
mod proof;
mod tree;

pub use builders::*;
pub use proof::*;
pub use tree::*;

/// A tree that is fully persisted to disk.
///
/// It's generic over the hash function `H`, the base arity `U`, sub-tree arity `V` and top-tree
/// arity `W`.
///
/// The base arity is used for for all levels up to the top. Non zero arties of the top-tree and/or
/// sub-tree each add another layer on top. So a tree with e.g. `U = 8`, `V = 4`, `W = 2` would
/// create a tree where the top level has two children, the levels below 4 children and all other
/// levels below have 8 children.
pub type DiskTree<H, U, V, W> = MerkleTreeWrapper<H, DiskStore<<H as Hasher>::Domain>, U, V, W>;

/// A tree that is partially stored on disk, some levels are in memory.
///
/// It's generic over the hash function `H`, the base arity `U`, sub-tree arity `V` and top tree
/// arity `W`.
///
/// The base arity is used for for all levels up to the top. Non zero arties of the top-tree and/or
/// sub-tree each add another layer on top. So a tree with e.g. `U = 8`, `V = 4`, `W = 2` would
/// create a tree where the top level has two children, the levels below 4 children and all other
/// levels below have 8 children.
pub type LCTree<H, U, V, W> =
    MerkleTreeWrapper<H, LevelCacheStore<<H as Hasher>::Domain, File>, U, V, W>;

/// A binary merkle tree, where all levels have arity 2. It's fully persisted to disk.
pub type BinaryMerkleTree<H> = DiskTree<H, U2, U0, U0>;
