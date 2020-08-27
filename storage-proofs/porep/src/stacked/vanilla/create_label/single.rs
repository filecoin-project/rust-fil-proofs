use sha2raw::Sha256;
use std::marker::PhantomData;

use anyhow::Result;
use generic_array::typenum::Unsigned;
use log::*;
use merkletree::store::{DiskStore, StoreConfig};
use storage_proofs_core::{
    cache_key::CacheKey,
    drgraph::Graph,
    hasher::Hasher,
    merkle::*,
    util::{data_at_node_offset, NODE_SIZE},
};

use super::super::{cache::ParentCache, Labels, LabelsCache, StackedBucketGraph};

#[allow(clippy::type_complexity)]
pub fn create_labels<Tree: 'static + MerkleTreeTrait, T: AsRef<[u8]>>(
    graph: &StackedBucketGraph<Tree::Hasher>,
    parents_cache: &mut ParentCache,
    layers: usize,
    replica_id: T,
    config: StoreConfig,
) -> Result<(LabelsCache<Tree>, Labels<Tree>)> {
    info!("generate labels");

    // For now, we require it due to changes in encodings structure.
    let mut labels: Vec<DiskStore<<Tree::Hasher as Hasher>::Domain>> = Vec::with_capacity(layers);
    let mut label_configs: Vec<StoreConfig> = Vec::with_capacity(layers);

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
        let layer_config =
            StoreConfig::from_config(&config, CacheKey::label_layer(layer), Some(graph.size()));

        info!("  storing labels on disk");
        // Construct and persist the layer data.
        let layer_store: DiskStore<<Tree::Hasher as Hasher>::Domain> =
            DiskStore::new_from_slice_with_config(
                graph.size(),
                Tree::Arity::to_usize(),
                &layer_labels,
                layer_config.clone(),
            )?;
        info!(
            "  generated layer {} store with id {}",
            layer, layer_config.id
        );

        info!("  setting exp parents");
        std::mem::swap(&mut layer_labels, &mut exp_labels);

        // Track the layer specific store and StoreConfig for later retrieval.
        labels.push(layer_store);
        label_configs.push(layer_config);
    }

    assert_eq!(
        labels.len(),
        layers,
        "Invalid amount of layers encoded expected"
    );

    Ok((
        LabelsCache::<Tree> { labels },
        Labels::<Tree> {
            labels: label_configs,
            _h: PhantomData,
        },
    ))
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
