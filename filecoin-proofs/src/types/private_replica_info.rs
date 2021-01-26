use std::cmp::Ordering;
use std::fs;
use std::hash::{Hash, Hasher as StdHasher};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bincode::deserialize;
use filecoin_hashers::Hasher;
use generic_array::typenum::Unsigned;
use log::trace;
use merkletree::store::StoreConfig;
use storage_proofs_core::{
    cache_key::CacheKey,
    merkle::{
        create_tree, get_base_tree_count, split_config_and_replica, MerkleTreeTrait,
        MerkleTreeWrapper,
    },
    util::default_rows_to_discard,
};

use crate::{
    api::{as_safe_commitment, get_base_tree_leafs, get_base_tree_size},
    types::{Commitment, PersistentAux, SectorSize},
};

/// The minimal information required about a replica, in order to be able to generate
/// a PoSt over it.
#[derive(Debug)]
pub struct PrivateReplicaInfo<Tree: MerkleTreeTrait> {
    /// Path to the replica.
    replica: PathBuf,
    /// The replica commitment.
    comm_r: Commitment,
    /// Persistent Aux.
    aux: PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    /// Contains sector-specific (e.g. merkle trees) assets
    pub cache_dir: PathBuf,

    _t: PhantomData<Tree>,
}

impl<Tree: MerkleTreeTrait> Clone for PrivateReplicaInfo<Tree> {
    fn clone(&self) -> Self {
        Self {
            replica: self.replica.clone(),
            comm_r: self.comm_r,
            aux: self.aux.clone(),
            cache_dir: self.cache_dir.clone(),
            _t: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait> PartialEq for PrivateReplicaInfo<Tree> {
    fn eq(&self, other: &Self) -> bool {
        self.replica == other.replica
            && self.comm_r == other.comm_r
            && self.aux == other.aux
            && self.cache_dir == other.cache_dir
    }
}

impl<Tree: MerkleTreeTrait> Hash for PrivateReplicaInfo<Tree> {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        self.replica.hash(state);
        self.comm_r.hash(state);
        self.aux.hash(state);
        self.cache_dir.hash(state);
    }
}

impl<Tree: MerkleTreeTrait> Eq for PrivateReplicaInfo<Tree> {}

impl<Tree: MerkleTreeTrait> Ord for PrivateReplicaInfo<Tree> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.comm_r.as_ref().cmp(other.comm_r.as_ref())
    }
}

impl<Tree: MerkleTreeTrait> PartialOrd for PrivateReplicaInfo<Tree> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.comm_r.as_ref().partial_cmp(other.comm_r.as_ref())
    }
}

impl<Tree: 'static + MerkleTreeTrait> PrivateReplicaInfo<Tree> {
    pub fn new(replica: PathBuf, comm_r: Commitment, cache_dir: PathBuf) -> Result<Self> {
        ensure!(comm_r != [0; 32], "Invalid all zero commitment (comm_r)");

        let aux = {
            let f_aux_path = cache_dir.join(CacheKey::PAux.to_string());
            let aux_bytes = fs::read(&f_aux_path)
                .with_context(|| format!("could not read from path={:?}", f_aux_path))?;

            deserialize(&aux_bytes)
        }?;

        ensure!(replica.exists(), "Sealed replica does not exist");

        Ok(PrivateReplicaInfo {
            replica,
            comm_r,
            aux,
            cache_dir,
            _t: Default::default(),
        })
    }

    pub fn cache_dir_path(&self) -> &Path {
        self.cache_dir.as_path()
    }

    pub fn replica_path(&self) -> &Path {
        self.replica.as_path()
    }

    pub fn safe_comm_r(&self) -> Result<<Tree::Hasher as Hasher>::Domain> {
        as_safe_commitment(&self.comm_r, "comm_r")
    }

    pub fn safe_comm_c(&self) -> <Tree::Hasher as Hasher>::Domain {
        self.aux.comm_c
    }

    pub fn safe_comm_r_last(&self) -> <Tree::Hasher as Hasher>::Domain {
        self.aux.comm_r_last
    }

    /// Generate the merkle tree of this particular replica.
    pub fn merkle_tree(
        &self,
        sector_size: SectorSize,
    ) -> Result<
        MerkleTreeWrapper<
            Tree::Hasher,
            Tree::Store,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    > {
        let base_tree_size = get_base_tree_size::<Tree>(sector_size)?;
        let base_tree_leafs = get_base_tree_leafs::<Tree>(base_tree_size)?;
        trace!(
            "post: base tree size {}, base tree leafs {}, rows_to_discard {}, arities [{}, {}, {}]",
            base_tree_size,
            base_tree_leafs,
            default_rows_to_discard(base_tree_leafs, Tree::Arity::to_usize()),
            Tree::Arity::to_usize(),
            Tree::SubTreeArity::to_usize(),
            Tree::TopTreeArity::to_usize(),
        );

        let mut config = StoreConfig::new(
            self.cache_dir_path(),
            CacheKey::CommRLastTree.to_string(),
            default_rows_to_discard(base_tree_leafs, Tree::Arity::to_usize()),
        );
        config.size = Some(base_tree_size);

        let tree_count = get_base_tree_count::<Tree>();
        let (configs, replica_config) = split_config_and_replica(
            config,
            self.replica_path().to_path_buf(),
            base_tree_leafs,
            tree_count,
        )?;

        create_tree::<Tree>(base_tree_size, &configs, Some(&replica_config))
    }
}
