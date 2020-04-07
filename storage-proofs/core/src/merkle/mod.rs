#![allow(clippy::len_without_is_empty)]

use generic_array::typenum::{U0, U2, U4, U8};

use crate::hasher::Hasher;

mod builders;
mod proof;
mod tree;

pub use builders::*;
pub use proof::*;
pub use tree::*;

// Reexport here, so we don't depend on merkletree directly in other places.
pub use merkletree::store::{ExternalReader, Store};

pub type DiskStore<E> = merkletree::store::DiskStore<E>;
pub type LCStore<E> = merkletree::store::LevelCacheStore<E, std::fs::File>;

pub type MerkleStore<T> = DiskStore<T>;

pub type DiskTree<H, U, V, W> = MerkleTreeWrapper<H, DiskStore<<H as Hasher>::Domain>, U, V, W>;
pub type LCTree<H, U, V, W> = MerkleTreeWrapper<H, LCStore<<H as Hasher>::Domain>, U, V, W>;

pub type MerkleTree<H, U> = DiskTree<H, U, U0, U0>;
pub type LCMerkleTree<H, U> = LCTree<H, U, U0, U0>;

pub type BinaryMerkleTree<H> = MerkleTree<H, U2>;
pub type BinaryLCMerkleTree<H> = LCMerkleTree<H, U2>;

pub type BinarySubMerkleTree<H> = DiskTree<H, U2, U2, U0>;

pub type QuadMerkleTree<H> = MerkleTree<H, U4>;
pub type QuadLCMerkleTree<H> = LCMerkleTree<H, U4>;

pub type OctMerkleTree<H> = DiskTree<H, U8, U0, U0>;
pub type OctSubMerkleTree<H> = DiskTree<H, U8, U2, U0>;
pub type OctTopMerkleTree<H> = DiskTree<H, U8, U8, U2>;

pub type OctLCMerkleTree<H> = LCTree<H, U8, U0, U0>;
pub type OctLCSubMerkleTree<H> = LCTree<H, U8, U2, U0>;
pub type OctLCTopMerkleTree<H> = LCTree<H, U8, U8, U2>;
