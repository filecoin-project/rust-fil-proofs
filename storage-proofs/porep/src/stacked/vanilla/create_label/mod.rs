use anyhow::Context;
use log::*;
use merkletree::merkle::Element;
use merkletree::store::StoreConfig;
use storage_proofs_core::{
    cache_key::CacheKey, drgraph::Graph, error::Result, hasher::Hasher, merkle::MerkleTreeTrait,
};

use crate::stacked::vanilla::{proof::LayerState, StackedBucketGraph};

pub mod multi;
pub mod single;

/// Prepares the necessary `StoreConfig`s with which the layers are stored.
/// Also checks for already existing layers and marks them as such.
pub fn prepare_layers<Tree: 'static + MerkleTreeTrait>(
    graph: &StackedBucketGraph<Tree::Hasher>,
    config: &StoreConfig,
    layers: usize,
) -> Vec<LayerState> {
    let label_configs = (1..=layers).map(|layer| {
        StoreConfig::from_config(&config, CacheKey::label_layer(layer), Some(graph.size()))
    });

    let mut states = Vec::with_capacity(layers);
    for (layer, label_config) in (1..=layers).zip(label_configs) {
        // Clear possible left over tmp files
        remove_tmp_layer(&label_config);

        // Check if this layer is already on disk
        let generated = is_layer_written::<Tree>(graph, &label_config).unwrap_or_default();
        if generated {
            // succesful load
            info!("found valid labels for layer {}", layer);
        }

        states.push(LayerState {
            config: label_config,
            generated,
        });
    }

    states
}

/// Stores a layer atomically on disk, by writing first to `.tmp` and then renaming.
pub fn write_layer(data: &[u8], config: &StoreConfig) -> Result<()> {
    let data_path = StoreConfig::data_path(&config.path, &config.id);
    let tmp_data_path = data_path.with_extension(".tmp");

    if let Some(parent) = data_path.parent() {
        std::fs::create_dir_all(parent).context("failed to create parent directories")?;
    }
    std::fs::write(&tmp_data_path, data).context("failed to write layer data")?;
    std::fs::rename(tmp_data_path, data_path).context("failed to rename tmp data")?;

    Ok(())
}

/// Reads a layer from disk, into the provided slice.
pub fn read_layer(config: &StoreConfig, mut data: &mut [u8]) -> Result<()> {
    let data_path = StoreConfig::data_path(&config.path, &config.id);
    let file = std::fs::File::open(data_path).context("failed to open layer")?;
    let mut buffered = std::io::BufReader::new(file);
    std::io::copy(&mut buffered, &mut data).context("failed to read layer")?;

    Ok(())
}

pub fn remove_tmp_layer(config: &StoreConfig) {
    let data_path = StoreConfig::data_path(&config.path, &config.id);
    let tmp_data_path = data_path.with_extension(".tmp");
    if tmp_data_path.exists() {
        if let Err(err) = std::fs::remove_file(tmp_data_path) {
            warn!("failed to delete tmp file: {}", err);
        }
    }
}

/// Checks if the given layer is already written and of the right size.
pub fn is_layer_written<Tree: 'static + MerkleTreeTrait>(
    graph: &StackedBucketGraph<Tree::Hasher>,
    config: &StoreConfig,
) -> Result<bool> {
    let data_path = StoreConfig::data_path(&config.path, &config.id);
    if !data_path.exists() {
        return Ok(false);
    }

    let file = std::fs::File::open(&data_path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;

    if file_size != graph.size() * <Tree::Hasher as Hasher>::Domain::byte_len() {
        return Ok(false);
    }

    Ok(true)
}
