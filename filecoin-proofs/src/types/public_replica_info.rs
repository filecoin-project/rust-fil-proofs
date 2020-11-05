use std::hash::{Hash, Hasher as StdHasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use bincode::deserialize;
use generic_array::typenum::Unsigned;
use log::{info, trace};
use merkletree::store::StoreConfig;
use storage_proofs::cache_key::CacheKey;
use storage_proofs::hasher::{Domain, Hasher};
use storage_proofs::merkle::{
    create_tree, get_base_tree_count, split_config_and_replica, MerkleTreeTrait, MerkleTreeWrapper,
};
use storage_proofs::util::default_rows_to_discard;

use crate::api::util::{as_safe_commitment, get_base_tree_leafs, get_base_tree_size};
use crate::types::{Commitment, PersistentAux, SectorSize};

/// The minimal information required about a replica, in order to be able to verify
/// a PoSt over it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicReplicaInfo {
    /// The replica commitment.
    comm_r: Commitment,
}

impl std::cmp::Ord for PublicReplicaInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl std::cmp::PartialOrd for PublicReplicaInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PublicReplicaInfo {
    pub fn new(comm_r: Commitment) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");
        Ok(PublicReplicaInfo { comm_r })
    }

    pub fn safe_comm_r<T: Domain>(&self) -> Result<T> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }
}
