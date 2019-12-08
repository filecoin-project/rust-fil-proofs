use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::path::Path;

use anyhow::{ensure, Context};
use log::trace;
use merkletree::merkle::get_merkle_tree_leafs;
use merkletree::store::{DiskStore, Store, StoreConfig};
use serde::{Deserialize, Serialize};

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::stacked::{
    column::Column, column_proof::ColumnProof, graph::StackedBucketGraph, proof::StackedConfig,
    EncodingProof, LabelingProof, LayerChallenges, OPENINGS_PER_WINDOW,
};
use crate::util::{data_at_node, NODE_SIZE};

pub type Tree<H> = MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

#[derive(Debug, Copy, Clone)]
pub enum CacheKey {
    PAux,
    TAux,
    CommDTree,
    CommCTree,
    CommQTree,
    CommRLastTree,
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CacheKey::PAux => write!(f, "p_aux"),
            CacheKey::TAux => write!(f, "t_aux"),
            CacheKey::CommDTree => write!(f, "tree-d"),
            CacheKey::CommCTree => write!(f, "tree-c"),
            CacheKey::CommQTree => write!(f, "tree-q"),
            CacheKey::CommRLastTree => write!(f, "tree-r-last"),
        }
    }
}

impl CacheKey {
    pub fn label_layer(layer: usize) -> String {
        format!("layer-{}", layer)
    }
}

#[derive(Debug, Clone)]
pub struct SetupParams {
    /// Number of nodes.
    pub nodes: usize,
    /// Base degree of DRG.
    pub degree: usize,
    /// Degree of th expander graph .
    pub expansion_degree: usize,
    /// Random seed
    pub seed: [u8; 28],
    /// Size of a window in nodes.
    pub window_size_nodes: usize,

    pub config: StackedConfig,
}

#[derive(Debug, Clone)]
pub struct PublicParams<H>
where
    H: 'static + Hasher,
{
    pub config: StackedConfig,
    pub window_graph: StackedBucketGraph<H>,
    pub wrapper_graph: StackedBucketGraph<H>,
    /// Window size in nodes.
    pub window_size: usize,
    _h: PhantomData<H>,
}

impl<H> PublicParams<H>
where
    H: Hasher,
{
    pub fn new(
        window_graph: StackedBucketGraph<H>,
        wrapper_graph: StackedBucketGraph<H>,
        config: StackedConfig,
        window_size: usize,
    ) -> Self {
        PublicParams {
            window_graph,
            wrapper_graph,
            config,
            window_size,
            _h: PhantomData,
        }
    }

    pub fn window_size_nodes(&self) -> usize {
        self.window_size
    }

    pub fn window_size_bytes(&self) -> usize {
        self.window_size * NODE_SIZE
    }

    pub fn num_windows(&self) -> usize {
        self.wrapper_graph.sector_size() as usize / self.window_size_bytes()
    }

    pub fn layer_size(&self) -> usize {
        self.wrapper_graph.size() * NODE_SIZE
    }
}

impl<H> ParameterSetMetadata for PublicParams<H>
where
    H: Hasher,
{
    fn identifier(&self) -> String {
        format!(
            "layered_drgporep::PublicParams{{ window_graph: {}, wrapper_graph: {}, config: {:?}, window_size: {} }}",
            self.window_graph.identifier(),
            self.wrapper_graph.identifier(),
            self.config,
            self.window_size,
        )
    }

    fn sector_size(&self) -> u64 {
        self.wrapper_graph.sector_size()
    }
}

impl<'a, H> From<&'a PublicParams<H>> for PublicParams<H>
where
    H: Hasher,
{
    fn from(other: &PublicParams<H>) -> PublicParams<H> {
        PublicParams::new(
            other.window_graph.clone(),
            other.wrapper_graph.clone(),
            other.config.clone(),
            other.window_size,
        )
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain, S: Domain> {
    pub replica_id: T,
    pub seed: [u8; 32],
    pub tau: Option<Tau<T, S>>,
    pub k: Option<usize>,
}

impl<T: Domain, S: Domain> PublicInputs<T, S> {
    pub fn all_challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Result<Vec<usize>> {
        let k = partition_k.unwrap_or(0);

        layer_challenges.derive_all::<T>(leaves, &self.replica_id, &self.seed, k as u8)
    }
}

#[derive(Debug)]
pub struct PrivateInputs<H: Hasher, G: Hasher> {
    pub p_aux: PersistentAux<H::Domain>,
    pub t_aux: TemporaryAuxCache<H, G>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher, G: Hasher> {
    #[serde(bound(
        serialize = "WindowProof<H, G>: Serialize",
        deserialize = "WindowProof<H, G>: Deserialize<'de>"
    ))]
    pub window_proofs: Vec<WindowProof<H, G>>,
    #[serde(bound(
        serialize = "WrapperProof<H>: Serialize",
        deserialize = "WrapperProof<H>: Deserialize<'de>"
    ))]
    pub wrapper_proofs: Vec<WrapperProof<H>>,
    pub comm_c: H::Domain,
    pub comm_q: H::Domain,
    pub comm_r_last: H::Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowProof<H: Hasher, G: Hasher> {
    /// One proof for every window.
    #[serde(bound(
        serialize = "MerkleProof<G>: Serialize",
        deserialize = "MerkleProof<G>: Deserialize<'de>"
    ))]
    pub comm_d_proofs: Vec<MerkleProof<G>>,
    /// One proof for every window.
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize, ColumnProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>, ColumnProof<H>: Deserialize<'de>"
    ))]
    pub comm_q_proofs: Vec<MerkleProof<H>>,
    #[serde(bound(
        serialize = "ReplicaColumnProof<H>: Serialize",
        deserialize = "ReplicaColumnProof<H>: Deserialize<'de>"
    ))]
    pub replica_column_proof: ReplicaColumnProof<H>,
    #[serde(bound(
        serialize = "LabelingProof<H>: Serialize",
        deserialize = "LabelingProof<H>: Deserialize<'de>"
    ))]
    /// One proof for every window.
    /// Indexed by layer in 1..layers.
    pub labeling_proofs: Vec<HashMap<usize, LabelingProof<H>>>,
    /// One proof for every window.
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    pub encoding_proofs: Vec<EncodingProof<H>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperProof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize, ColumnProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>, ColumnProof<H>: Deserialize<'de>"
    ))]
    pub comm_r_last_proof: MerkleProof<H>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize, ColumnProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>, ColumnProof<H>: Deserialize<'de>"
    ))]
    pub comm_q_parents_proofs: Vec<MerkleProof<H>>,
    #[serde(bound(
        serialize = "LabelingProof<H>: Serialize",
        deserialize = "LabelingProof<H>: Deserialize<'de>"
    ))]
    pub labeling_proof: LabelingProof<H>,
}

impl<H: Hasher> WrapperProof<H> {
    pub fn comm_r_last(&self) -> &H::Domain {
        self.comm_r_last_proof.root()
    }

    pub fn verify<G: Hasher>(
        &self,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
        challenge: usize,
        wrapper_graph: &StackedBucketGraph<H>,
        comm_q: &H::Domain,
    ) -> Result<bool> {
        let replica_id = &pub_inputs.replica_id;

        check!(challenge < wrapper_graph.size());
        check!(pub_inputs.tau.is_some());

        trace!("verify final replica layer openings");
        check!(self.comm_r_last_proof.proves_challenge(challenge));

        trace!("verify comm_q_parents");
        let mut parents = vec![0; wrapper_graph.expansion_degree()];
        wrapper_graph.expanded_parents(challenge, &mut parents)?;

        for (proof, parent) in self.comm_q_parents_proofs.iter().zip(parents.iter()) {
            check_eq!(proof.root(), comm_q);
            check!(proof.validate(*parent as usize));
        }

        trace!("verify labeling");
        let labeled_node = self.comm_r_last_proof.leaf();
        check!(self.labeling_proof.verify(replica_id, labeled_node)?);

        Ok(true)
    }
}

impl<H: Hasher, G: Hasher> WindowProof<H, G> {
    pub fn comm_c(&self) -> &H::Domain {
        self.replica_column_proof.c_x.root()
    }

    /// Verify the full proof.
    pub fn verify(
        &self,
        pub_params: &PublicParams<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
        challenge: usize,
        comm_q: &H::Domain,
        comm_c: &H::Domain,
    ) -> Result<bool> {
        let window_graph = &pub_params.window_graph;
        let replica_id = &pub_inputs.replica_id;

        check!(challenge < window_graph.size());
        check!(pub_inputs.tau.is_some());

        check_eq!(self.comm_d_proofs.len(), OPENINGS_PER_WINDOW);
        check_eq!(self.comm_q_proofs.len(), OPENINGS_PER_WINDOW);
        check_eq!(self.encoding_proofs.len(), OPENINGS_PER_WINDOW);

        // Verify initial data layer
        trace!("verify initial data layer");
        check!(self.verify_comm_d_proofs(challenge, pub_params, pub_inputs)?);

        // Verify q data layer
        trace!("verify q data layer");
        check!(self.verify_comm_q_proofs(pub_params, challenge, comm_q)?);

        // Verify replica column openings
        trace!("verify replica column openings");
        check!(self
            .replica_column_proof
            .verify(challenge, &pub_params.window_graph, comm_c)?);

        check!(self.verify_labels(replica_id, pub_params.config.layers())?);

        trace!("verify encoding");
        check!(self.verify_encoding_proofs(replica_id)?);

        Ok(true)
    }

    fn verify_encoding_proofs(&self, replica_id: &H::Domain) -> Result<bool> {
        for (encoding_proof, (comm_q_proof, comm_d_proof)) in self
            .encoding_proofs
            .iter()
            .zip(self.comm_q_proofs.iter().zip(self.comm_d_proofs.iter()))
        {
            check!(encoding_proof.verify::<G>(
                replica_id,
                comm_q_proof.leaf(),
                comm_d_proof.leaf(),
            )?);
        }
        Ok(true)
    }

    fn verify_comm_d_proofs(
        &self,
        challenge: usize,
        pub_params: &PublicParams<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
    ) -> Result<bool> {
        for (window_index, comm_d_proof) in self.comm_d_proofs.iter().enumerate() {
            let c = window_index * pub_params.window_size_nodes() + challenge;
            check!(comm_d_proof.proves_challenge(c));
            if let Some(ref tau) = pub_inputs.tau {
                check_eq!(comm_d_proof.root(), &tau.comm_d);
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn verify_comm_q_proofs(
        &self,
        pub_params: &PublicParams<H>,
        challenge: usize,
        comm_q: &H::Domain,
    ) -> Result<bool> {
        for (window_index, comm_q_proof) in self.comm_q_proofs.iter().enumerate() {
            let c = window_index * pub_params.window_size_nodes() + challenge;
            check!(comm_q_proof.proves_challenge(c));
            check_eq!(comm_q_proof.root(), comm_q);
        }
        Ok(true)
    }

    /// Verify all encodings.
    fn verify_labels(&self, replica_id: &H::Domain, layers: usize) -> Result<bool> {
        for (window_index, labeling_proofs) in self.labeling_proofs.iter().enumerate() {
            // Verify Labels Layer 1..layers
            check_eq!(labeling_proofs.len(), layers - 1);
            for (layer, proof) in labeling_proofs.iter() {
                trace!(
                    "verify labeling (layer: {}, window: {}",
                    layer,
                    window_index
                );
                check!(proof.window_index.is_some());
                check_eq!(window_index as u64, proof.window_index.unwrap());

                let expected_labeled_node = self
                    .replica_column_proof
                    .c_x
                    .get_node_at_layer(window_index, *layer)?;

                check!(proof.verify(replica_id, expected_labeled_node)?);
            }
        }
        Ok(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaColumnProof<H: Hasher> {
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub c_x: ColumnProof<H>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub drg_parents: Vec<ColumnProof<H>>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub exp_parents: Vec<ColumnProof<H>>,
}

impl<H: Hasher> ReplicaColumnProof<H> {
    pub fn verify(
        &self,
        challenge: usize,
        window_graph: &StackedBucketGraph<H>,
        expected_comm_c: &H::Domain,
    ) -> Result<bool> {
        let mut parents = vec![0; window_graph.degree()];
        window_graph.parents(challenge, &mut parents)?;

        trace!("  verify c_x");
        check_eq!(self.c_x.root(), expected_comm_c);
        check!(self.c_x.verify(challenge as u32, &expected_comm_c)?);

        trace!("  verify drg_parents");
        for (proof, parent) in self.drg_parents.iter().zip(parents.iter()) {
            check!(proof.verify(*parent, &expected_comm_c)?);
        }

        trace!("  verify exp_parents");
        for (proof, parent) in self
            .exp_parents
            .iter()
            .zip(parents.iter().skip(self.drg_parents.len()))
        {
            check!(proof.verify(*parent, &expected_comm_c)?);
        }

        Ok(true)
    }
}

pub type TransformedLayers<H, G> = (
    Tau<<H as Hasher>::Domain, <G as Hasher>::Domain>,
    PersistentAux<<H as Hasher>::Domain>,
    TemporaryAux<H, G>,
);

/// Tau for a single parition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tau<D: Domain, E: Domain> {
    pub comm_d: E,
    pub comm_r: D,
}

/// Stored along side the sector on disk.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersistentAux<D> {
    pub comm_c: D,
    pub comm_q: D,
    pub comm_r_last: D,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporaryAux<H: Hasher, G: Hasher> {
    /// The encoded nodes for 1..layers.
    pub labels: Labels<H>,
    pub tree_d_config: StoreConfig,
    pub tree_r_last_config: StoreConfig,
    pub tree_c_config: StoreConfig,
    pub tree_q_config: StoreConfig,
    pub _g: PhantomData<G>,
}

impl<H: Hasher, G: Hasher> TemporaryAux<H, G> {
    pub fn set_cache_path<P: AsRef<Path>>(&mut self, cache_path: P) {
        let cp = cache_path.as_ref().to_path_buf();
        for label in self.labels.labels.iter_mut() {
            label.path = cp.clone();
        }
        self.tree_d_config.path = cp.clone();
        self.tree_r_last_config.path = cp.clone();
        self.tree_c_config.path = cp.clone();
        self.tree_q_config.path = cp;
    }

    pub fn labels_for_layer(&self, layer: usize) -> Result<DiskStore<H::Domain>> {
        self.labels.labels_for_layer(layer)
    }

    pub fn domain_node_at_layer(&self, layer: usize, node_index: u32) -> Result<H::Domain> {
        Ok(self.labels_for_layer(layer)?.read_at(node_index as usize)?)
    }

    pub fn column(&self, layers: usize, column_index: u32) -> Result<Column<H>> {
        self.labels.column(layers, column_index)
    }

    pub fn delete(t_aux: TemporaryAux<H, G>) -> Result<()> {
        // TODO: once optimized, compact tree_r_last to only store the top part of the tree.

        let tree_d_size = t_aux
            .tree_d_config
            .size
            .context("tree_d config has no size")?;
        let tree_d_store: DiskStore<G::Domain> =
            DiskStore::new_from_disk(tree_d_size, &t_aux.tree_d_config).context("tree_d")?;
        let tree_d: Tree<G> =
            MerkleTree::from_data_store(tree_d_store, get_merkle_tree_leafs(tree_d_size))
                .context("tree_d")?;
        tree_d.delete(t_aux.tree_d_config).context("tree_d")?;

        let tree_c_size = t_aux
            .tree_c_config
            .size
            .context("tree_c config has no size")?;
        let tree_c_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_c_size, &t_aux.tree_c_config).context("tree_c")?;
        let tree_c: Tree<H> =
            MerkleTree::from_data_store(tree_c_store, get_merkle_tree_leafs(tree_c_size))
                .context("tree_c")?;
        tree_c.delete(t_aux.tree_c_config).context("tree_c")?;

        let tree_q_size = t_aux
            .tree_q_config
            .size
            .context("tree_q config has no size")?;
        let tree_q_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_q_size, &t_aux.tree_q_config).context("tree_q")?;
        let tree_q: Tree<H> =
            MerkleTree::from_data_store(tree_q_store, get_merkle_tree_leafs(tree_q_size))
                .context("tree_q")?;
        tree_q.delete(t_aux.tree_q_config).context("tree_q")?;

        for i in 0..t_aux.labels.labels.len() {
            DiskStore::<H::Domain>::delete(t_aux.labels.labels[i].clone())
                .with_context(|| format!("labels {}", i))?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct TemporaryAuxCache<H: Hasher, G: Hasher> {
    /// The encoded nodes for 1..layers.
    pub labels: LabelsCache<H>,
    pub tree_d: Tree<G>,
    pub tree_q: Tree<H>,
    pub tree_r_last: Tree<H>,
    pub tree_c: Tree<H>,
    pub t_aux: TemporaryAux<H, G>,
}

impl<H: Hasher, G: Hasher> TemporaryAuxCache<H, G> {
    pub fn new(t_aux: &TemporaryAux<H, G>) -> Result<Self> {
        trace!("restoring tree_d from {:?}", &t_aux.tree_d_config);

        let tree_d_size = t_aux
            .tree_d_config
            .size
            .context("tree_d config has no size")?;
        let tree_d_store: DiskStore<G::Domain> =
            DiskStore::new_from_disk(tree_d_size, &t_aux.tree_d_config).context("tree_d")?;
        let tree_d: Tree<G> =
            MerkleTree::from_data_store(tree_d_store, get_merkle_tree_leafs(tree_d_size))?;

        trace!("restoring tree_c from {:?}", &t_aux.tree_c_config);
        let tree_c_size = t_aux
            .tree_c_config
            .size
            .context("tree_c config has no size")?;
        let tree_c_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_c_size, &t_aux.tree_c_config).context("tree_c")?;
        let tree_c: Tree<H> =
            MerkleTree::from_data_store(tree_c_store, get_merkle_tree_leafs(tree_c_size))?;

        trace!("restoring tree_r_last from {:?}", &t_aux.tree_r_last_config);
        let tree_r_last_size = t_aux
            .tree_r_last_config
            .size
            .context("tree_r config has no size")?;
        let tree_r_last_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_r_last_size, &t_aux.tree_r_last_config)
                .context("tree_r")?;
        let tree_r_last: Tree<H> = MerkleTree::from_data_store(
            tree_r_last_store,
            get_merkle_tree_leafs(tree_r_last_size),
        )?;

        trace!("restoring tree_q from {:?}", &t_aux.tree_q_config);
        let tree_q_size = t_aux
            .tree_q_config
            .size
            .context("tree_q config has no size")?;
        let tree_q_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_q_size, &t_aux.tree_q_config).context("tree_q")?;
        let tree_q: Tree<H> =
            MerkleTree::from_data_store(tree_q_store, get_merkle_tree_leafs(tree_q_size))?;

        Ok(TemporaryAuxCache {
            labels: LabelsCache::new(&t_aux.labels)?,
            tree_d,
            tree_r_last,
            tree_c,
            tree_q,
            t_aux: t_aux.clone(),
        })
    }

    pub fn labels_for_layer(&self, layer: usize) -> Result<&DiskStore<H::Domain>> {
        self.labels.labels_for_layer(layer)
    }

    pub fn domain_node_at_layer(&self, layer: usize, node_index: u32) -> Result<H::Domain> {
        self.labels_for_layer(layer)?.read_at(node_index as usize)
    }

    pub fn column(&self, column_index: u32, pub_params: &PublicParams<H>) -> Result<Column<H>> {
        self.labels.column(column_index, pub_params)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Labels<H: Hasher> {
    pub labels: Vec<StoreConfig>,
    pub _h: PhantomData<H>,
}

impl<H: Hasher> Labels<H> {
    pub fn new(labels: Vec<StoreConfig>) -> Self {
        Labels {
            labels,
            _h: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn labels_for_layer(&self, layer: usize) -> Result<DiskStore<H::Domain>> {
        ensure!(layer != 0, "Layer cannot be 0");
        ensure!(
            layer <= self.layers(),
            "Layer {} is not available (only {} layers available)",
            layer,
            self.layers()
        );

        let row_index = layer - 1;
        let config = self.labels[row_index].clone();
        ensure!(config.size.is_some(), "There needs to be a config.");

        DiskStore::new_from_disk(config.size.unwrap(), &config)
    }

    /// Returns label for the last layer.
    pub fn labels_for_last_layer(&self) -> Result<DiskStore<H::Domain>> {
        self.labels_for_layer(self.labels.len() - 1)
    }

    /// How many layers are available.
    fn layers(&self) -> usize {
        self.labels.len()
    }

    /// Build the column for the given node.
    pub fn column(&self, layers: usize, node: u32) -> Result<Column<H>> {
        let rows = self
            .labels
            .iter()
            .map(|label| {
                ensure!(label.size.is_some(), "Label must have a size.");
                let store = DiskStore::new_from_disk(label.size.unwrap(), &label)?;
                store.read_at(node as usize)
            })
            .collect::<Result<_>>()?;

        Column::new(node, layers, rows)
    }
}

#[derive(Debug)]
pub struct LabelsCache<H: Hasher> {
    pub labels: Vec<DiskStore<H::Domain>>,
    pub _h: PhantomData<H>,
}

impl<H: Hasher> LabelsCache<H> {
    pub fn from_stores(labels: Vec<DiskStore<H::Domain>>) -> Self {
        LabelsCache {
            labels,
            _h: PhantomData,
        }
    }

    pub fn new(labels: &Labels<H>) -> Result<Self> {
        let mut disk_store_labels: Vec<DiskStore<H::Domain>> = Vec::with_capacity(labels.len());
        for i in 0..labels.len() {
            disk_store_labels.push(labels.labels_for_layer(i + 1)?);
        }

        Ok(LabelsCache {
            labels: disk_store_labels,
            _h: PhantomData,
        })
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn labels_for_layer(&self, layer: usize) -> Result<&DiskStore<H::Domain>> {
        ensure!(layer != 0, "Layer cannot be 0");
        ensure!(
            layer <= self.layers(),
            "Layer {} is not available (only {} layers available)",
            layer,
            self.layers()
        );

        let row_index = layer - 1;
        Ok(&self.labels[row_index])
    }

    /// Returns the labels on the last layer.
    pub fn labels_for_last_layer(&self) -> &DiskStore<H::Domain> {
        &self.labels[self.labels.len() - 1]
    }

    /// How many layers are available.
    fn layers(&self) -> usize {
        self.labels.len()
    }

    /// Build the column for the given node.
    pub fn column(&self, node: u32, pub_params: &PublicParams<H>) -> Result<Column<H>> {
        ensure!(
            (node as usize) < pub_params.window_size_nodes(),
            "Node must be small than window size."
        );

        let len = self.layers();
        ensure!(len > 1, "invalid layer number");

        let num_windows = pub_params.num_windows();
        ensure!(num_windows > 0, "invalid number of windows");

        let rows = (0..num_windows)
            .flat_map(|window_index| {
                self.labels
                    .iter()
                    .take(len - 1) // skip last one
                    .map(move |labels| {
                        labels
                            .read_at(window_index * pub_params.window_size_nodes() + node as usize)
                    })
            })
            .collect::<Result<_>>()?;

        Column::new(node, len - 1, rows)
    }
}

pub fn get_node<H: Hasher>(data: &[u8], index: usize) -> Result<H::Domain> {
    H::Domain::try_from_bytes(data_at_node(data, index).context("invalid node math")?)
}

/// Generate the replica id as expected for Stacked DRG.
pub fn generate_replica_id<H: Hasher, T: AsRef<[u8]>>(
    prover_id: &[u8; 32],
    sector_id: u64,
    ticket: &[u8; 32],
    comm_d: T,
) -> H::Domain {
    use sha2::{Digest, Sha256};

    let hash = Sha256::new()
        .chain(prover_id)
        .chain(&sector_id.to_be_bytes()[..])
        .chain(ticket)
        .chain(AsRef::<[u8]>::as_ref(&comm_d))
        .result();

    bytes_into_fr_repr_safe(hash.as_ref()).into()
}
