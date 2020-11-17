use std::iter;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bellperson::bls::Fr;
use filecoin_hashers::{Domain, Hasher, POSEIDON_CONSTANTS_15_BASE, POSEIDON_CONSTANTS_2_BASE};
use generic_array::typenum::{Unsigned, U2};
use merkletree::merkle::get_merkle_tree_leafs;
use merkletree::store::{Store, StoreConfig};
use neptune::poseidon::Poseidon;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    merkle::{
        split_config, split_config_and_replica, BinaryMerkleTree, DiskStore, LCStore, MerkleProof,
        MerkleProofTrait, MerkleTreeTrait, MerkleTreeWrapper,
    },
    parameter_cache::ParameterSetMetadata,
};

use super::Config;

/// Implementation of  Narrow Stacked Expander PoRep (NSE).
#[derive(Debug, Default)]
pub struct NarrowStackedExpander<'a, Tree: MerkleTreeTrait, G: 'a + Hasher> {
    _tree: PhantomData<&'a Tree>,
    _g: PhantomData<G>,
}

pub const MAX_COMM_R_ARITY: usize = 15;

#[derive(Debug, Clone)]
pub struct SetupParams {
    pub config: Config,
    /// Number of layer challenges.
    pub num_layer_challenges: usize,
}

#[derive(Debug)]
pub struct PublicParams<Tree> {
    pub config: Config,
    /// Number of layer challenges.
    pub num_layer_challenges: usize,
    _tree: PhantomData<Tree>,
}

impl<Tree> Clone for PublicParams<Tree> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            num_layer_challenges: self.num_layer_challenges,
            _tree: Default::default(),
        }
    }
}

impl<Tree> From<SetupParams> for PublicParams<Tree> {
    fn from(setup_params: SetupParams) -> Self {
        Self {
            config: setup_params.config,
            num_layer_challenges: setup_params.num_layer_challenges,
            _tree: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait> ParameterSetMetadata for PublicParams<Tree> {
    fn identifier(&self) -> String {
        format!(
            "nse::PublicParams{{ config: {:?}, layer_challenges {}, tree: {} }}",
            self.config,
            self.num_layer_challenges,
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
    // The roots of all layer trees.
    pub layer_roots: Vec<D>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TemporaryAux<Tree: MerkleTreeTrait, G: Hasher> {
    pub layer_config: StoreConfig,
    /// Data tree config.
    pub tree_d_config: StoreConfig,
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for TemporaryAux<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            layer_config: self.layer_config.clone(),
            tree_d_config: self.tree_d_config.clone(),
            _tree: Default::default(),
            _g: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> TemporaryAux<Tree, G> {
    /// Create a new TemporaryAux from the required store configs.
    pub fn new(layer_config: StoreConfig, tree_d_config: StoreConfig) -> Self {
        Self {
            layer_config,
            tree_d_config,
            _tree: Default::default(),
            _g: Default::default(),
        }
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

        // TODO: use split
        // for configs in self.layer_configs.into_iter() {
        //     for config in configs.into_iter() {
        //         if cached(&config) {
        //             DiskStore::<<Tree::Hasher as Hasher>::Domain>::delete(config)?;
        //         }
        //     }
        // }

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
    pub tau: Tau<D, S>,
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

    pub tree_replica: MerkleTreeWrapper<
        Tree::Hasher,
        LCStore<<Tree::Hasher as Hasher>::Domain>,
        Tree::Arity,
        Tree::SubTreeArity,
        Tree::TopTreeArity,
    >,

    /// The merkle tree for the original data .
    pub tree_d: BinaryMerkleTree<G>,

    // Store the 'cached_above_base layers' value from the `StoreConfig` for later use (i.e. proof generation).
    pub tree_config_rows_to_discard: usize,

    pub t_aux: TemporaryAux<Tree, G>,

    /// The path to the replica.
    pub replica_path: PathBuf,
}

impl<Tree: MerkleTreeTrait, G: Hasher> TemporaryAuxCache<Tree, G> {
    pub fn new(
        config: &Config,
        t_aux: &TemporaryAux<Tree, G>,
        replica_path: PathBuf,
    ) -> Result<Self> {
        // tree_d_size stored in the config is the base tree size
        let tree_d_size = t_aux.tree_d_config.size.unwrap();
        let tree_d_leafs = get_merkle_tree_leafs(tree_d_size, U2::to_usize())?;

        let tree_d_store: DiskStore<G::Domain> =
            DiskStore::new_from_disk(tree_d_size, U2::to_usize(), &t_aux.tree_d_config)
                .context("tree_d_store")?;
        let tree_d =
            BinaryMerkleTree::<G>::from_data_store(tree_d_store, tree_d_leafs).context("tree_d")?;

        // split configs for layer level
        let store_configs = split_config(t_aux.layer_config.clone(), config.num_layers())?;

        let mut layers = store_configs
            .into_iter()
            .enumerate()
            .map(|(layer_index, store_config)| {
                if layer_index < config.num_layers() - 1 {
                    // split for window level
                    let store_configs = split_config(store_config, config.num_windows())?;

                    // create tree for this layer
                    MerkleTreeWrapper::<
                        Tree::Hasher,
                        LCStore<<Tree::Hasher as Hasher>::Domain>,
                        Tree::Arity,
                        Tree::SubTreeArity,
                        Tree::TopTreeArity,
                    >::from_store_configs(
                        config.num_nodes_window, &store_configs
                    )
                } else {
                    // with replica, last layer
                    // split for window level
                    let (store_configs, replica_config) = split_config_and_replica(
                        store_config,
                        replica_path.clone(),
                        config.num_nodes_window,
                        config.num_windows(),
                    )?;

                    // create tree for this layer
                    MerkleTreeWrapper::<
                        Tree::Hasher,
                        LCStore<<Tree::Hasher as Hasher>::Domain>,
                        Tree::Arity,
                        Tree::SubTreeArity,
                        Tree::TopTreeArity,
                    >::from_store_configs_and_replica(
                        config.num_nodes_window,
                        &store_configs,
                        &replica_config,
                    )
                }
            })
            .collect::<Result<Vec<_>>>()?;

        let tree_replica = layers.pop().unwrap(); // replica tree is the last one
        let tree_config_rows_to_discard = t_aux.layer_config.rows_to_discard;

        Ok(TemporaryAuxCache {
            layers,
            tree_replica,
            tree_d,
            tree_config_rows_to_discard,
            replica_path,
            t_aux: t_aux.clone(),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof<Tree: MerkleTreeTrait, G: Hasher> {
    /// The proofs for each `LayerChallenge`.
    #[serde(bound(
        serialize = "LayerProof<Tree, G>: Serialize",
        deserialize = "LayerProof<Tree, G>: Deserialize<'de>"
    ))]
    pub layer_proofs: Vec<LayerProof<Tree, G>>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> Proof<Tree, G> {
    pub fn layer_roots(&self) -> Vec<<Tree::Hasher as Hasher>::Domain> {
        self.layer_proofs[0].layer_roots()
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for Proof<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            layer_proofs: self.layer_proofs.clone(),
        }
    }
}

/// A proof of a single `LayerChallenge`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LayerProof<Tree: MerkleTreeTrait, G: Hasher> {
    #[serde(bound(
        serialize = "NodeProof<Tree, G>: Serialize",
        deserialize = "NodeProof<Tree, G>: Deserialize<'de>"
    ))]
    pub first_layer_proof: NodeProof<Tree, G>,
    #[serde(bound(
        serialize = "NodeProof<Tree, G>: Serialize",
        deserialize = "NodeProof<Tree, G>: Deserialize<'de>"
    ))]
    pub expander_layer_proofs: Vec<NodeProof<Tree, G>>,
    #[serde(bound(
        serialize = "NodeProof<Tree, G>: Serialize",
        deserialize = "NodeProof<Tree, G>: Deserialize<'de>"
    ))]
    pub butterfly_layer_proofs: Vec<NodeProof<Tree, G>>,
    #[serde(bound(
        serialize = "NodeProof<Tree, G>: Serialize",
        deserialize = "NodeProof<Tree, G>: Deserialize<'de>"
    ))]
    pub last_layer_proof: NodeProof<Tree, G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> LayerProof<Tree, G> {
    pub fn layer_roots(&self) -> Vec<<Tree::Hasher as Hasher>::Domain> {
        iter::once(&self.first_layer_proof)
            .chain(self.expander_layer_proofs.iter())
            .chain(self.butterfly_layer_proofs.iter())
            .chain(iter::once(&self.last_layer_proof))
            .map(|node_proof| node_proof.layer_proof.root())
            .collect()
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for LayerProof<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            first_layer_proof: self.first_layer_proof.clone(),
            expander_layer_proofs: self.expander_layer_proofs.clone(),
            butterfly_layer_proofs: self.butterfly_layer_proofs.clone(),
            last_layer_proof: self.last_layer_proof.clone(),
        }
    }
}

/// A proof of a single `Challenge`.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeProof<Tree: MerkleTreeTrait, G: Hasher> {
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
    #[serde(bound(
        serialize = "MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>: Serialize",
        deserialize = "MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>: Deserialize<'de>"
    ))]
    pub parents_proofs:
        Vec<MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>>,
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> NodeProof<Tree, G> {
    pub fn new(
        data_proof: MerkleProof<G, U2>,
        layer_proof: MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        parents_proofs: Vec<
            MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        >,
    ) -> Self {
        Self {
            data_proof,
            layer_proof,
            parents_proofs,
            _tree: Default::default(),
            _g: Default::default(),
        }
    }
}

impl<Tree: MerkleTreeTrait, G: Hasher> Clone for NodeProof<Tree, G> {
    fn clone(&self) -> Self {
        Self {
            data_proof: self.data_proof.clone(),
            layer_proof: self.layer_proof.clone(),
            parents_proofs: self.parents_proofs.clone(),
            _tree: Default::default(),
            _g: Default::default(),
        }
    }
}

/// Hash all but the last layer's root to produce comm_layers.
pub fn hash_comm_layers<D: Domain>(layer_roots_sans_last: &[D]) -> Fr {
    let len = layer_roots_sans_last.len();
    assert!(
        len > 0 && len <= 15,
        "layer roots exceed chosen Poseidon constants"
    );
    let consts = POSEIDON_CONSTANTS_15_BASE.with_length(len);
    let layer_roots_sans_last: Vec<Fr> = layer_roots_sans_last
        .iter()
        .map(|&layer_root| layer_root.into())
        .collect();
    let mut hasher = Poseidon::new_with_preimage(&layer_roots_sans_last, &consts);
    hasher.hash()
}

/// Hashes comm_layers with the last layer's root (root_r).
pub fn hash_comm_r<D: Domain>(comm_layers: D, root_r: D) -> Fr {
    let preimg: [Fr; 2] = [comm_layers.into(), root_r.into()];
    let mut hasher = Poseidon::new_with_preimage(&preimg[..], &*POSEIDON_CONSTANTS_2_BASE);
    hasher.hash()
}
