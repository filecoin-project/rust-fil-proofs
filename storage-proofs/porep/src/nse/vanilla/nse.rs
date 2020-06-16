use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use generic_array::typenum::{Unsigned, U2};
use merkletree::merkle::get_merkle_tree_leafs;
use merkletree::store::{Store, StoreConfig};
use paired::bls12_381::Fr;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{
    hasher::{Domain, HashFunction, Hasher, PoseidonDomain, PoseidonFunction, PoseidonMDArity},
    merkle::{
        split_config, split_config_and_replica, BinaryMerkleTree, DiskStore, LCStore, MerkleProof,
        MerkleTreeTrait, MerkleTreeWrapper,
    },
    parameter_cache::ParameterSetMetadata,
};

use super::Config;

/// Implementation of  Narrow Stacked Expander PoRep (NSE).
#[derive(Debug, Default)]
pub struct NarrowStackedExpander<'a, Tree: 'a + MerkleTreeTrait, G: 'a + Hasher> {
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
    /// The commitment of the replica.
    pub comm_replica: D,
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
    /// The roots of the merkle tree layers, including the replica layer.
    pub comm_layers: Vec<<Tree::Hasher as Hasher>::Domain>,
    _tree: PhantomData<Tree>,
    _g: PhantomData<G>,
}

impl<Tree: MerkleTreeTrait, G: Hasher> Proof<Tree, G> {
    pub fn new(
        data_proof: MerkleProof<G, U2>,
        layer_proof: MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        parents_proofs: Vec<
            MerkleProof<Tree::Hasher, Tree::Arity, Tree::SubTreeArity, Tree::TopTreeArity>,
        >,
        comm_layers: Vec<<Tree::Hasher as Hasher>::Domain>,
    ) -> Self {
        Self {
            data_proof,
            layer_proof,
            parents_proofs,
            comm_layers,
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
            parents_proofs: self.parents_proofs.clone(),
            comm_layers: self.comm_layers.clone(),
            _tree: Default::default(),
            _g: Default::default(),
        }
    }
}

/// Calculate the comm_r hash.
pub fn hash_comm_r<D: Domain>(comm_layers: &[D], comm_replica: D) -> Fr {
    let arity = PoseidonMDArity::to_usize();
    let mut data: Vec<PoseidonDomain> = Vec::with_capacity(arity);
    data.extend(comm_layers.iter().map(|v| {
        let fr: Fr = (*v).into();
        let d: PoseidonDomain = fr.into();
        d
    }));
    let comm_replica_fr: Fr = comm_replica.into();
    data.push(comm_replica_fr.into());

    // pad for MD
    while data.len() % arity != 0 {
        data.push(PoseidonDomain::default());
    }

    PoseidonFunction::hash_md(&data).into()
}
