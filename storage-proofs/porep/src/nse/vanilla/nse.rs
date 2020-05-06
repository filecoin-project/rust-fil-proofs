use std::marker::PhantomData;
use std::path::PathBuf;

use generic_array::typenum::U8;
use merkletree::store::StoreConfig;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    hasher::{Domain, Hasher},
    merkle::{BinaryMerkleTree, LCTree, MerkleTreeTrait},
    parameter_cache::ParameterSetMetadata,
};

use super::Config;

/// Implementation of  Narrow Stacked Expander PoRep (NSE).
#[derive(Debug, Default)]
pub struct NarrowStackedExpander<'a, Tree: MerkleTreeTrait, G: Hasher> {
    _tree: PhantomData<&'a Tree>,
    _g: PhantomData<G>,
}

#[derive(Debug, Clone)]
pub struct SetupParams {
    pub config: Config,
}

#[derive(Debug)]
pub struct PublicParams<Tree> {
    pub config: Config,
    _tree: PhantomData<Tree>,
}

impl<Tree> Clone for PublicParams<Tree> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            _tree: Default::default(),
        }
    }
}

impl<Tree> From<SetupParams> for PublicParams<Tree> {
    fn from(setup_params: SetupParams) -> Self {
        Self {
            config: setup_params.config,
            _tree: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait> ParameterSetMetadata for PublicParams<Tree> {
    fn identifier(&self) -> String {
        format!(
            "nse::PublicParams{{ config: {:?}, tree: {} }}",
            self.config,
            Tree::display()
        )
    }

    fn sector_size(&self) -> u64 {
        self.config.sector_size as u64
    }
}

/// Stored along side the sector on disk.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersistentAux<D> {
    /// The commitments for the individual layers.
    pub comm_layers: Vec<D>,
}

impl<D: Domain> PersistentAux<D> {
    /// The commitment of the replica.
    pub fn comm_replica(&self) -> &D {
        &self.comm_layers[self.comm_layers.len() - 1]
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TemporaryAux<Tree: MerkleTreeTrait, G: Hasher> {
    /// List of layer trees configs.
    pub layer_configs: Vec<StoreConfig>,
    /// Data tree config.
    pub tree_d_config: StoreConfig,
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> TemporaryAux<Tree, G> {
    /// The store config of the replica.
    pub fn replica_config(&self) -> &StoreConfig {
        &self.layer_configs[self.layer_configs.len() - 1]
    }
}

/// Tau.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tau<D: Domain, E: Domain> {
    /// The commitment for the original data.
    pub comm_d: E,
    /// The commitment to the full replica.
    pub comm_r: D,
}

#[derive(Debug, Clone)]
pub struct PublicInputs<D: Domain, S: Domain> {
    pub replica_id: D,
    pub seed: [u8; 32],
    pub tau: Option<Tau<D, S>>,
    /// Partition index
    pub k: Option<usize>,
}

#[derive(Debug)]
pub struct PrivateInputs<Tree: MerkleTreeTrait, G: Hasher> {
    pub p_aux: PersistentAux<<Tree::Hasher as Hasher>::Domain>,
    pub t_aux: TemporaryAuxCache<Tree, G>,
}

#[derive(Debug)]
pub struct TemporaryAuxCache<Tree: MerkleTreeTrait, G: Hasher> {
    /// The merkle trees for each layer.
    pub layers: Vec<LCTree<Tree::Hasher, U8, Tree::SubTreeArity, Tree::TopTreeArity>>,

    /// The merkle tree for the original data .
    pub tree_d: BinaryMerkleTree<G>,

    // Store the 'cached_above_base layers' value from the `StoreConfig` for later use (i.e. proof generation).
    pub tree_config_levels: usize,

    pub t_aux: TemporaryAux<Tree, G>,

    /// The path to the replica.
    pub replica_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof<Tree: MerkleTreeTrait, G: Hasher> {
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for Proof<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            _tree: Default::default(),
            _g: Default::default(),
        }
    }
}
