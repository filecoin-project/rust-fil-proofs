use anyhow::{ensure, Result};
use ff::Field;
use itertools::Itertools;
use sha2raw::Sha256;
use storage_proofs_core::{fr32::bytes_into_fr, hasher::Domain, util::NODE_SIZE};

use super::{
    batch_hasher::{batch_hash, truncate_hash},
    butterfly_graph::ButterflyGraph,
    expander_graph::ExpanderGraph,
    Config,
};

/// Generate the mask layer, for one window.
pub fn mask_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_out: &mut [u8],
) -> Result<()> {
    ensure!(
        layer_out.len() == config.n,
        "layer_out must be of size {}, got {}",
        config.n,
        layer_out.len()
    );

    // The mask layer is always layer 1.
    const LAYER_INDEX: u32 = 1;

    // Construct the mask
    for (node_index, node) in layer_out.chunks_mut(NODE_SIZE).enumerate() {
        let prefix = hash_prefix(LAYER_INDEX, node_index as u32, window_index);
        let hash = Sha256::digest(&[&prefix[..], AsRef::<[u8]>::as_ref(replica_id)]);
        node.copy_from_slice(&hash);
        truncate_hash(node);
    }

    Ok(())
}

/// Generate a single expander layer, for one window.
pub fn expander_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    layer_out: &mut [u8],
) -> Result<()> {
    ensure!(
        layer_in.len() == layer_out.len(),
        "layer_in and layer_out must of the same size"
    );
    ensure!(
        layer_out.len() == config.n,
        "layer_out must be of size {}, got {}",
        config.n,
        layer_out.len()
    );

    let graph: ExpanderGraph = config.into();

    // Iterate over each node.
    for (node_index, node) in layer_out.chunks_mut(NODE_SIZE).enumerate() {
        let node_index = node_index as u32;

        // Compute the parents for this node.
        let parents: Vec<_> = graph.parents(node_index).collect();

        let mut hasher = Sha256::new();

        // Hash prefix + replica id, each 32 bytes.
        let prefix = hash_prefix(layer_index, node_index, window_index);
        hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(replica_id)]);

        // Compute batch hash of the parents.
        let hash = batch_hash(
            config.k as usize,
            config.degree_expander,
            hasher,
            &parents,
            layer_in,
        );
        node.copy_from_slice(&hash);
        truncate_hash(node);
    }

    Ok(())
}

/// Generate a single butterfly layer.
pub fn butterfly_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    layer_out: &mut [u8],
) -> Result<()> {
    ensure!(
        layer_in.len() == layer_out.len(),
        "layer_in and layer_out must of the same size"
    );
    ensure!(
        layer_out.len() == config.n,
        "layer_out must be of size {}, got {}",
        config.n,
        layer_out.len()
    );

    let graph: ButterflyGraph = config.into();

    // Iterate over each node.
    for (node_index, node) in layer_out.chunks_mut(NODE_SIZE).enumerate() {
        let node_index = node_index as u32;

        let mut hasher = Sha256::new();

        // Hash prefix + replica id, each 32 bytes.
        let prefix = hash_prefix(layer_index, node_index, window_index);
        hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(replica_id)]);

        // Compute hash of the parents.
        for (parent_a, parent_b) in graph.parents(node_index, layer_index).tuples() {
            let parent_a = parent_a as usize;
            let parent_b = parent_b as usize;
            let parent_a_value = &layer_in[parent_a * NODE_SIZE..(parent_a + 1) * NODE_SIZE];
            let parent_b_value = &layer_in[parent_b * NODE_SIZE..(parent_b + 1) * NODE_SIZE];

            hasher.input(&[parent_a_value, parent_b_value]);
        }

        let hash = hasher.finish();
        node.copy_from_slice(&hash);
        truncate_hash(node);
    }

    Ok(())
}

/// Generate a butterfly layer which additionally encodes using the data.
pub fn butterfly_encode_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    data: &[u8], // TODO: might want to overwrite the data
    layer_out: &mut [u8],
) -> Result<()> {
    ensure!(
        layer_in.len() == layer_out.len(),
        "layer_in and layer_out must of the same size"
    );
    ensure!(
        layer_out.len() == config.n,
        "layer_out must be of size {}, got {}",
        config.n,
        layer_out.len()
    );

    let graph: ButterflyGraph = config.into();

    // Iterate over each node.
    for (node_index, (node, data_node)) in layer_out
        .chunks_mut(NODE_SIZE)
        .zip(data.chunks(NODE_SIZE))
        .enumerate()
    {
        let node_index = node_index as u32;

        let mut hasher = Sha256::new();

        // Hash prefix + replica id, each 32 bytes.
        let prefix = hash_prefix(layer_index, node_index, window_index);
        hasher.input(&[&prefix[..], AsRef::<[u8]>::as_ref(replica_id)]);

        // Compute hash of the parents.
        for (parent_a, parent_b) in graph.parents(node_index, layer_index).tuples() {
            let parent_a = parent_a as usize;
            let parent_b = parent_b as usize;
            let parent_a_value = &layer_in[parent_a * NODE_SIZE..(parent_a + 1) * NODE_SIZE];
            let parent_b_value = &layer_in[parent_b * NODE_SIZE..(parent_b + 1) * NODE_SIZE];

            hasher.input(&[parent_a_value, parent_b_value]);
        }

        let mut key = hasher.finish();
        truncate_hash(&mut key);

        // encode
        let key = bytes_into_fr(&key)?;
        let mut encoded_node = bytes_into_fr(data_node)?;
        encoded_node.add_assign(&key);
        let domain_encoded_node: D = encoded_node.into();

        // write result
        node.copy_from_slice(AsRef::<[u8]>::as_ref(&domain_encoded_node));
    }

    Ok(())
}

/// Constructs the first 32 byte prefix for hashing any node.
pub fn hash_prefix(layer: u32, node_index: u32, window_index: u32) -> [u8; 32] {
    let mut prefix = [0u8; 32];
    // layer: 32bits
    prefix[..4].copy_from_slice(&layer.to_be_bytes());
    // node_index: 32bits
    prefix[4..8].copy_from_slice(&node_index.to_be_bytes());
    // window_index: 32bits
    prefix[8..12].copy_from_slice(&window_index.to_be_bytes());
    // 0 padding for the rest

    prefix
}
