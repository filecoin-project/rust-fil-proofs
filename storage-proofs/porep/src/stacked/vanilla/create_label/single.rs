use sha2raw::Sha256;
use std::marker::PhantomData;

use anyhow::{Context, Result};
use generic_array::typenum::Unsigned;
use log::*;
use merkletree::store::{DiskStore, StoreConfig};
use storage_proofs_core::{
    drgraph::Graph,
    hasher::Hasher,
    merkle::*,
    util::{data_at_node_offset, NODE_SIZE},
};

use super::super::{
    cache::ParentCache, proof::LayerState, Labels, LabelsCache, StackedBucketGraph,
};

#[allow(clippy::type_complexity)]
pub fn create_labels_for_encoding<Tree: 'static + MerkleTreeTrait, T: AsRef<[u8]>>(
    graph: &StackedBucketGraph<Tree::Hasher>,
    parents_cache: &mut ParentCache,
    layers: usize,
    replica_id: T,
    config: StoreConfig,
) -> Result<(Labels<Tree>, Vec<LayerState>)> {
    info!("generate labels");

    let layer_states = super::prepare_layers::<Tree>(graph, &config, layers);

    let layer_size = graph.size() * NODE_SIZE;
    // NOTE: this means we currently keep 2x sector size around, to improve speed.
    let mut layer_labels = vec![0u8; layer_size]; // Buffer for labels of the current layer
    let mut exp_labels = vec![0u8; layer_size]; // Buffer for labels of the previous layer, needed for expander parents

    for (layer, layer_state) in (1..=layers).zip(layer_states.iter()) {
        info!("generating layer: {}", layer);
        if layer_state.generated {
            info!("skipping layer {}, already generated", layer);

            // load the already generated layer into exp_labels
            super::read_layer(&layer_state.config, &mut exp_labels)?;
            continue;
        }

        parents_cache.reset()?;

        if layer == 1 {
            for node in 0..graph.size() {
                create_label(
                    graph,
                    Some(parents_cache),
                    &replica_id,
                    &mut layer_labels,
                    layer,
                    node,
                )?;
            }
        } else {
            for node in 0..graph.size() {
                create_label_exp(
                    graph,
                    Some(parents_cache),
                    &replica_id,
                    &exp_labels,
                    &mut layer_labels,
                    layer,
                    node,
                )?;
            }
        }

        // Write the result to disk to avoid keeping it in memory all the time.
        let layer_config = &layer_state.config;

        info!("  storing labels on disk");
        super::write_layer(&layer_labels, layer_config).context("failed to store labels")?;

        info!(
            "  generated layer {} store with id {}",
            layer, layer_config.id
        );

        info!("  setting exp parents");
        std::mem::swap(&mut layer_labels, &mut exp_labels);
    }

    Ok((
        Labels::<Tree> {
            labels: layer_states.iter().map(|s| s.config.clone()).collect(),
            _h: PhantomData,
        },
        layer_states,
    ))
}

#[allow(clippy::type_complexity)]
pub fn create_labels_for_decoding<Tree: 'static + MerkleTreeTrait, T: AsRef<[u8]>>(
    graph: &StackedBucketGraph<Tree::Hasher>,
    parents_cache: &mut ParentCache,
    layers: usize,
    replica_id: T,
    config: StoreConfig,
) -> Result<LabelsCache<Tree>> {
    info!("generate labels");

    // For now, we require it due to changes in encodings structure.
    let mut labels: Vec<DiskStore<<Tree::Hasher as Hasher>::Domain>> = Vec::with_capacity(layers);

    let layer_size = graph.size() * NODE_SIZE;
    // NOTE: this means we currently keep 2x sector size around, to improve speed.
    let mut layer_labels = vec![0u8; layer_size]; // Buffer for labels of the current layer
    let mut exp_labels = vec![0u8; layer_size]; // Buffer for labels of the previous layer, needed for expander parents

    for layer in 1..=layers {
        info!("generating layer: {}", layer);

        parents_cache.reset()?;

        if layer == 1 {
            for node in 0..graph.size() {
                create_label(
                    graph,
                    Some(parents_cache),
                    &replica_id,
                    &mut layer_labels,
                    layer,
                    node,
                )?;
            }
        } else {
            for node in 0..graph.size() {
                create_label_exp(
                    graph,
                    Some(parents_cache),
                    &replica_id,
                    &exp_labels,
                    &mut layer_labels,
                    layer,
                    node,
                )?;
            }
        }

        // Write the result to disk to avoid keeping it in memory all the time.
        info!("  storing labels on disk");
        super::write_layer(&layer_labels, &config)?;

        let layer_store: DiskStore<<Tree::Hasher as Hasher>::Domain> =
            DiskStore::new_from_disk(graph.size(), Tree::Arity::to_usize(), &config)?;
        info!("  generated layer {} store with id {}", layer, config.id);

        info!("  setting exp parents");
        std::mem::swap(&mut layer_labels, &mut exp_labels);

        // Track the layer specific store and StoreConfig for later retrieval.
        labels.push(layer_store);
    }

    assert_eq!(
        labels.len(),
        layers,
        "Invalid amount of layers encoded expected"
    );

    Ok(LabelsCache::<Tree> { labels })
}

pub fn create_label<H: Hasher, T: AsRef<[u8]>>(
    graph: &StackedBucketGraph<H>,
    cache: Option<&mut ParentCache>,
    replica_id: T,
    layer_labels: &mut [u8],
    layer_index: usize,
    node: usize,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32];

    buffer[..4].copy_from_slice(&(layer_index as u32).to_be_bytes());
    buffer[4..12].copy_from_slice(&(node as u64).to_be_bytes());
    hasher.input(&[replica_id.as_ref(), &buffer[..]][..]);

    // hash parents for all non 0 nodes
    let hash = if node > 0 {
        // prefetch previous node, which is always a parent
        let prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
        prefetch!(prev.as_ptr() as *const i8);

        graph.copy_parents_data(node as u32, &*layer_labels, hasher, cache)?
    } else {
        hasher.finish()
    };

    // store the newly generated key
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;
    layer_labels[start..end].copy_from_slice(&hash[..]);

    // strip last two bits, to ensure result is in Fr.
    layer_labels[end - 1] &= 0b0011_1111;

    Ok(())
}

pub fn create_label_exp<H: Hasher, T: AsRef<[u8]>>(
    graph: &StackedBucketGraph<H>,
    cache: Option<&mut ParentCache>,
    replica_id: T,
    exp_parents_data: &[u8],
    layer_labels: &mut [u8],
    layer_index: usize,
    node: usize,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32];

    buffer[0..4].copy_from_slice(&(layer_index as u32).to_be_bytes());
    buffer[4..12].copy_from_slice(&(node as u64).to_be_bytes());
    hasher.input(&[replica_id.as_ref(), &buffer[..]][..]);

    // hash parents for all non 0 nodes
    let hash = if node > 0 {
        // prefetch previous node, which is always a parent
        let prev = &layer_labels[(node - 1) * NODE_SIZE..node * NODE_SIZE];
        prefetch!(prev.as_ptr() as *const i8);

        graph.copy_parents_data_exp(node as u32, &*layer_labels, exp_parents_data, hasher, cache)?
    } else {
        hasher.finish()
    };

    // store the newly generated key
    let start = data_at_node_offset(node);
    let end = start + NODE_SIZE;
    layer_labels[start..end].copy_from_slice(&hash[..]);

    // strip last two bits, to ensure result is in Fr.
    layer_labels[end - 1] &= 0b0011_1111;

    Ok(())
}
