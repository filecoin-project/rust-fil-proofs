use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use generic_array::typenum::{Unsigned, U2};
use merkletree::merkle::{get_merkle_tree_leafs, get_merkle_tree_len, MerkleTree};
use merkletree::store::{ExternalReader, LevelCacheStore, Store, StoreConfig};
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    hasher::{Domain, Hasher},
    merkle::{
        BinaryMerkleTree, DiskStore, LCStore, MerkleProof, MerkleTreeTrait, MerkleTreeWrapper,
    },
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
    /// Number of challengs per window.
    pub num_challenges_window: usize,
}

#[derive(Debug)]
pub struct PublicParams<Tree> {
    pub config: Config,
    /// Number of challengs per window.
    pub num_challenges_window: usize,
    _tree: PhantomData<Tree>,
}

impl<Tree> Clone for PublicParams<Tree> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            num_challenges_window: self.num_challenges_window,
            _tree: Default::default(),
        }
    }
}

impl<Tree> From<SetupParams> for PublicParams<Tree> {
    fn from(setup_params: SetupParams) -> Self {
        Self {
            config: setup_params.config,
            num_challenges_window: setup_params.num_challenges_window,
            _tree: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait> ParameterSetMetadata for PublicParams<Tree> {
    fn identifier(&self) -> String {
        format!(
            "nse::PublicParams{{ config: {:?}, challenges/window {}, tree: {} }}",
            self.config,
            self.num_challenges_window,
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
    /// List of layer trees configs. Stores a config for each subtree.
    pub layer_configs: Vec<Vec<StoreConfig>>,
    /// Data tree config.
    pub tree_d_config: StoreConfig,
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for TemporaryAux<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            layer_configs: self.layer_configs.clone(),
            tree_d_config: self.tree_d_config.clone(),
            _tree: Default::default(),
            _g: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> TemporaryAux<Tree, G> {
    /// Create a new TemporaryAux from the required store configs.
    pub fn new(layer_configs: Vec<Vec<StoreConfig>>, tree_d_config: StoreConfig) -> Self {
        Self {
            layer_configs,
            tree_d_config,
            _tree: Default::default(),
            _g: Default::default(),
        }
    }

    /// The store config of the replica subtrees.
    pub fn replica_config(&self) -> &[StoreConfig] {
        &self.layer_configs[self.layer_configs.len() - 1]
    }

    // Discards all persisted merkle and layer data that is no longer required.
    pub fn clear_temp(self) -> Result<()> {
        let cached = |config: &StoreConfig| {
            Path::new(&StoreConfig::data_path(&config.path, &config.id)).exists()
        };

        if cached(&self.tree_d_config) {
            let tree_d_size = self
                .tree_d_config
                .size
                .context("tree_d config has no size")?;
            let tree_d_store: DiskStore<G::Domain> =
                DiskStore::new_from_disk(tree_d_size, U2::to_usize(), &self.tree_d_config)
                    .context("tree_d")?;
            // Note: from_data_store requires the base tree leaf count
            let tree_d = BinaryMerkleTree::<G>::from_data_store(
                tree_d_store,
                get_merkle_tree_leafs(tree_d_size, U2::to_usize())?,
            )
            .context("tree_d")?;

            tree_d.delete(self.tree_d_config).context("tree_d")?;
        }

        for configs in self.layer_configs.into_iter() {
            for config in configs.into_iter() {
                if cached(&config) {
                    DiskStore::<<Tree::Hasher as Hasher>::Domain>::delete(config)?;
                }
            }
        }

        Ok(())
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
    pub layers: Vec<
        MerkleTreeWrapper<
            Tree::Hasher,
            LCStore<<Tree::Hasher as Hasher>::Domain>,
            Tree::Arity,
            Tree::SubTreeArity,
            Tree::TopTreeArity,
        >,
    >,

    /// The merkle tree for the original data .
    pub tree_d: BinaryMerkleTree<G>,

    // Store the 'cached_above_base layers' value from the `StoreConfig` for later use (i.e. proof generation).
    pub tree_config_levels: usize,

    pub t_aux: TemporaryAux<Tree, G>,

    /// The path to the replica.
    pub replica_path: PathBuf,
}

impl<Tree: MerkleTreeTrait, G: Hasher> TemporaryAuxCache<Tree, G> {
    pub fn new(t_aux: &TemporaryAux<Tree, G>, replica_path: PathBuf) -> Result<Self> {
        // tree_d_size stored in the config is the base tree size
        let tree_d_size = t_aux.tree_d_config.size.unwrap();
        let tree_d_leafs = get_merkle_tree_leafs(tree_d_size, U2::to_usize())?;

        let tree_d_store: DiskStore<G::Domain> =
            DiskStore::new_from_disk(tree_d_size, U2::to_usize(), &t_aux.tree_d_config)
                .context("tree_d_store")?;
        let tree_d =
            BinaryMerkleTree::<G>::from_data_store(tree_d_store, tree_d_leafs).context("tree_d")?;

        let layers = t_aux
            .layer_configs
            .iter()
            .map(|store_configs| {
                let trees: Vec<_> = store_configs
                    .iter()
                    .enumerate()
                    .map(|(window_index, store_config)| {
                        restore_lc_tree::<Tree>(window_index, store_config, &replica_path)
                    })
                    .collect::<Result<_>>()?;

                MerkleTreeWrapper::<
                    Tree::Hasher,
                    LCStore<<Tree::Hasher as Hasher>::Domain>,
                    Tree::Arity,
                    Tree::SubTreeArity,
                    Tree::TopTreeArity,
                >::from_trees(trees)
            })
            .collect::<Result<Vec<_>>>()?;

        let tree_config_levels = t_aux.layer_configs[0][0].levels;

        Ok(TemporaryAuxCache {
            layers,
            tree_d,
            tree_config_levels,
            replica_path,
            t_aux: t_aux.clone(),
        })
    }
}

fn restore_lc_tree<Tree: MerkleTreeTrait>(
    window_index: usize,
    store_config: &StoreConfig,
    replica_path: &PathBuf,
) -> Result<MerkleTreeWrapper<Tree::Hasher, LCStore<<Tree::Hasher as Hasher>::Domain>, Tree::Arity>>
{
    let size = store_config.size.unwrap();
    let branches = Tree::Arity::to_usize();
    let num_leafs = get_merkle_tree_leafs(size, branches)?;
    let len = get_merkle_tree_len(num_leafs, branches)?;

    let data = LCStore::new_from_disk_with_reader(
        len,
        branches,
        store_config,
        ExternalReader::new_from_path(&replica_path.with_extension(format!("w{}", window_index)))?,
    )
    .context("failed to instantiate levelcache store")?;

    MerkleTreeWrapper::from_data_store(data, num_leafs)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof<Tree: MerkleTreeTrait, G: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<G, U2>: Serialize",
        deserialize = "MerkleProof<G, U2>: Deserialize<'de>"
    ))]
    pub data_proof: MerkleProof<G, U2>,
    #[serde(bound(
        serialize = "MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>: Deserialize<'de>"
    ))]
    pub layer_proof: MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> Proof<Tree, G> {
    pub fn new(
        data_proof: MerkleProof<G, U2>,
        layer_proof: MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
    ) -> Self {
        Self {
            data_proof,
            layer_proof,
            _tree: Default::default(),
            _g: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for Proof<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            data_proof: self.data_proof.clone(),
            layer_proof: self.layer_proof.clone(),
            _tree: Default::default(),
            _g: Default::default(),
        }
    }
}
