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
use crate::encode;

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
    ensure!(
        layer_index > 1 && layer_index as usize <= config.num_expander_layers,
        "layer index must be in range (1, {}]",
        config.num_expander_layers,
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
    ensure!(
        layer_index as usize > config.num_expander_layers
            && (layer_index as usize) < config.num_expander_layers + config.num_butterfly_layers,
        "layer index must be in range ({}, {})",
        config.num_expander_layers,
        config.num_expander_layers + config.num_butterfly_layers
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
            dbg!(parent_a, parent_b, node_index, layer_index);
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
    data: &[u8],
    layer_out: &mut [u8],
) -> Result<()> {
    butterfly_encode_decode_layer(
        config,
        window_index,
        replica_id,
        layer_index,
        layer_in,
        data,
        layer_out,
        encode::encode,
    )
}

/// Generate a butterfly layer which additionally decodes using the data.
pub fn butterfly_decode_layer<D: Domain>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    data: &[u8],
    layer_out: &mut [u8],
) -> Result<()> {
    butterfly_encode_decode_layer(
        config,
        window_index,
        replica_id,
        layer_index,
        layer_in,
        data,
        layer_out,
        encode::decode,
    )
}

/// Generate a butterfly layer which additionally encodes or decodes using the data.
fn butterfly_encode_decode_layer<D: Domain, F: Fn(D, D) -> D>(
    config: &Config,
    window_index: u32,
    replica_id: &D,
    layer_index: u32,
    layer_in: &[u8],
    data: &[u8], // TODO: might want to overwrite the data
    layer_out: &mut [u8],
    op: F,
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
    ensure!(
        layer_index as usize == config.num_expander_layers + config.num_butterfly_layers,
        "encoding must be on the last layer"
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
        let key = D::try_from_bytes(&key)?;
        let data_node = D::try_from_bytes(data_node)?;
        let encoded_node = op(key, data_node);

        // write result
        node.copy_from_slice(AsRef::<[u8]>::as_ref(&encoded_node));
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

#[cfg(test)]
mod tests {
    use super::*;

    use paired::bls12_381::Fr;
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use storage_proofs_core::{fr32::fr_into_bytes, hasher::Sha256Domain};

    fn sample_config() -> Config {
        Config {
            k: 8,
            n: 1024,
            degree_expander: 4,
            degree_butterfly: 4,
            num_expander_layers: 6,
            num_butterfly_layers: 4,
        }
    }

    #[test]
    fn test_mask_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: Sha256Domain = Fr::random(rng).into();
        let window_index = rng.gen();

        let mut layer: Vec<u8> = (0..config.n).map(|_| rng.gen()).collect();

        mask_layer(&config, window_index, &replica_id, &mut layer).unwrap();

        assert!(!layer.iter().all(|&byte| byte == 0), "must not all be zero");
    }

    #[test]
    fn test_expander_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: Sha256Domain = Fr::random(rng).into();
        let window_index = rng.gen();
        let layer_index = rng.gen_range(2, config.num_expander_layers as u32);

        let layer_in: Vec<u8> = (0..config.n / 32)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();
        let mut layer_out = vec![0u8; config.n];

        expander_layer(
            &config,
            window_index,
            &replica_id,
            layer_index,
            &layer_in,
            &mut layer_out,
        )
        .unwrap();

        assert!(
            !layer_out.iter().all(|&byte| byte == 0),
            "must not all be zero"
        );
    }

    #[test]
    fn test_butterfly_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: Sha256Domain = Fr::random(rng).into();
        let window_index = rng.gen();
        let layer_index = rng.gen_range(
            config.num_expander_layers,
            config.num_expander_layers + config.num_butterfly_layers,
        ) as u32;

        let layer_in: Vec<u8> = (0..config.n / 32)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();
        let mut layer_out = vec![0u8; config.n];

        butterfly_layer(
            &config,
            window_index,
            &replica_id,
            layer_index,
            &layer_in,
            &mut layer_out,
        )
        .unwrap();

        assert!(
            !layer_out.iter().all(|&byte| byte == 0),
            "must not all be zero"
        );
    }

    #[test]
    fn test_butterfly_encode_decode_layer() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let config = sample_config();
        let replica_id: Sha256Domain = Fr::random(rng).into();
        let window_index = rng.gen();
        let layer_index = (config.num_expander_layers + config.num_butterfly_layers) as u32;

        let data: Vec<u8> = (0..config.n / 32)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let layer_in: Vec<u8> = (0..config.n / 32)
            .flat_map(|_| fr_into_bytes(&Fr::random(rng)))
            .collect();

        let mut layer_out = vec![0u8; config.n];

        butterfly_encode_layer(
            &config,
            window_index,
            &replica_id,
            layer_index,
            &layer_in,
            &data,
            &mut layer_out,
        )
        .unwrap();

        assert!(
            !layer_out.iter().all(|&byte| byte == 0),
            "must not all be zero"
        );

        let mut data_back = vec![0u8; config.n];
        butterfly_decode_layer(
            &config,
            window_index,
            &replica_id,
            layer_index,
            &layer_in,
            &layer_out,
            &mut data_back,
        )
        .unwrap();
        assert_eq!(data, data_back, "failed to decode");
    }

    #[test]
    fn test_hash_prefix() {
        assert_eq!(hash_prefix(0, 0, 0), [0u8; 32]);
        assert_eq!(
            hash_prefix(1, 2, 3),
            [
                0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        );
    }
}
