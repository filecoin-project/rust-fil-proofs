use std::fs::File;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use log::*;
use merkletree::store::{DiskStore, LevelCacheStore, StoreConfig};
use storage_proofs_core::{
    cache_key::CacheKey,
    hasher::Hasher,
    merkle::{get_base_tree_count, MerkleTreeTrait},
};
use typenum::Unsigned;

use crate::types::{
    DefaultBinaryTree, DefaultOctTree, DefaultPieceDomain, DefaultPieceHasher, PersistentAux,
    SealPreCommitPhase1Output, TemporaryAux,
};

/// Checks for the existence of the tree d store, the replica, and all generated labels.
pub fn validate_cache_for_precommit_phase2<R, T, Tree: MerkleTreeTrait>(
    cache_path: R,
    replica_path: T,
    seal_precommit_phase1_output: &SealPreCommitPhase1Output<Tree>,
) -> Result<()>
where
    R: AsRef<Path>,
    T: AsRef<Path>,
{
    info!("validate_cache_for_precommit_phase2:start");

    ensure!(
        replica_path.as_ref().exists(),
        "Missing replica: {}",
        replica_path.as_ref().to_path_buf().display()
    );

    // Verify all stores/labels within the Labels object, but
    // respecting the current cache_path.
    let cache = cache_path.as_ref().to_path_buf();
    seal_precommit_phase1_output
        .labels
        .verify_stores(verify_store, &cache)?;

    // Update the previous phase store path to the current cache_path.
    let mut config = StoreConfig::from_config(
        &seal_precommit_phase1_output.config,
        &seal_precommit_phase1_output.config.id,
        seal_precommit_phase1_output.config.size,
    );
    config.path = cache_path.as_ref().into();

    let result = verify_store(
        &config,
        <DefaultBinaryTree as MerkleTreeTrait>::Arity::to_usize(),
        get_base_tree_count::<Tree>(),
    );

    info!("validate_cache_for_precommit_phase2:finish");
    result
}

// Checks for the existence of the replica data and t_aux, which in
// turn allows us to verify the tree d, tree r, tree c, and the
// labels.
pub fn validate_cache_for_commit<R, T, Tree: MerkleTreeTrait>(
    cache_path: R,
    replica_path: T,
) -> Result<()>
where
    R: AsRef<Path>,
    T: AsRef<Path>,
{
    info!("validate_cache_for_precommit:start");

    // Verify that the replica exists and is not empty.
    ensure!(
        replica_path.as_ref().exists(),
        "Missing replica: {}",
        replica_path.as_ref().to_path_buf().display()
    );

    let metadata = File::open(&replica_path)?.metadata()?;
    ensure!(
        metadata.len() > 0,
        "Replica {} exists, but is empty!",
        replica_path.as_ref().to_path_buf().display()
    );

    let cache = &cache_path.as_ref();

    // Make sure p_aux exists and is valid.
    let p_aux_path = cache.join(CacheKey::PAux.to_string());
    let p_aux_bytes = std::fs::read(&p_aux_path)
        .with_context(|| format!("could not read file p_aux={:?}", p_aux_path))?;

    let _: PersistentAux<<Tree::Hasher as Hasher>::Domain> = bincode::deserialize(&p_aux_bytes)?;
    drop(p_aux_bytes);

    // Make sure t_aux exists and is valid.
    let t_aux = {
        let t_aux_path = cache.join(CacheKey::TAux.to_string());
        let t_aux_bytes = std::fs::read(&t_aux_path)
            .with_context(|| format!("could not read file t_aux={:?}", t_aux_path))?;

        let mut res: TemporaryAux<Tree, DefaultPieceHasher> = bincode::deserialize(&t_aux_bytes)?;

        // Switch t_aux to the passed in cache_path
        res.set_cache_path(&cache_path);
        res
    };

    // Verify all stores/labels within the Labels object.
    let cache = cache_path.as_ref().to_path_buf();
    t_aux.labels.verify_stores(verify_store, &cache)?;

    // Verify each tree disk store.
    verify_store(
        &t_aux.tree_d_config,
        <DefaultBinaryTree as MerkleTreeTrait>::Arity::to_usize(),
        get_base_tree_count::<Tree>(),
    )?;
    verify_store(
        &t_aux.tree_c_config,
        <DefaultOctTree as MerkleTreeTrait>::Arity::to_usize(),
        get_base_tree_count::<Tree>(),
    )?;
    verify_level_cache_store::<DefaultOctTree>(&t_aux.tree_r_last_config)?;

    info!("validate_cache_for_precommit:finish");
    Ok(())
}

// Verifies if a DiskStore specified by a config (or set of 'required_configs' is consistent).
fn verify_store(config: &StoreConfig, arity: usize, required_configs: usize) -> Result<()> {
    let store_path = StoreConfig::data_path(&config.path, &config.id);
    if !Path::new(&store_path).exists() {
        // Configs may have split due to sector size, so we need to
        // check deterministic paths from here.
        let orig_path = store_path
            .clone()
            .into_os_string()
            .into_string()
            .expect("failed to convert store_path to string");
        let mut configs: Vec<StoreConfig> = Vec::with_capacity(required_configs);
        for i in 0..required_configs {
            let cur_path = orig_path
                .clone()
                .replace(".dat", format!("-{}.dat", i).as_str());

            if Path::new(&cur_path).exists() {
                let path_str = cur_path.as_str();
                let tree_names = vec!["tree-d", "tree-c", "tree-r-last"];
                for name in tree_names {
                    if path_str.find(name).is_some() {
                        configs.push(StoreConfig::from_config(
                            config,
                            format!("{}-{}", name, i),
                            None,
                        ));
                        break;
                    }
                }
            }
        }

        ensure!(
            configs.len() == required_configs,
            "Missing store file (or associated split paths): {}",
            store_path.display()
        );

        let store_len = config.size.expect("disk store size not configured");
        for config in &configs {
            ensure!(
                DiskStore::<DefaultPieceDomain>::is_consistent(store_len, arity, &config,)?,
                "Store is inconsistent: {:?}",
                StoreConfig::data_path(&config.path, &config.id)
            );
        }
    } else {
        ensure!(
            DiskStore::<DefaultPieceDomain>::is_consistent(
                config.size.expect("disk store size not configured"),
                arity,
                &config,
            )?,
            "Store is inconsistent: {:?}",
            store_path
        );
    }

    Ok(())
}

// Verifies if a LevelCacheStore specified by a config is consistent.
fn verify_level_cache_store<Tree: MerkleTreeTrait>(config: &StoreConfig) -> Result<()> {
    let store_path = StoreConfig::data_path(&config.path, &config.id);
    if !Path::new(&store_path).exists() {
        let required_configs = get_base_tree_count::<Tree>();

        // Configs may have split due to sector size, so we need to
        // check deterministic paths from here.
        let orig_path = store_path
            .clone()
            .into_os_string()
            .into_string()
            .expect("failed to convert store_path to string");
        let mut configs: Vec<StoreConfig> = Vec::with_capacity(required_configs);
        for i in 0..required_configs {
            let cur_path = orig_path
                .clone()
                .replace(".dat", format!("-{}.dat", i).as_str());

            if Path::new(&cur_path).exists() {
                let path_str = cur_path.as_str();
                let tree_names = vec!["tree-d", "tree-c", "tree-r-last"];
                for name in tree_names {
                    if path_str.find(name).is_some() {
                        configs.push(StoreConfig::from_config(
                            config,
                            format!("{}-{}", name, i),
                            None,
                        ));
                        break;
                    }
                }
            }
        }

        ensure!(
            configs.len() == required_configs,
            "Missing store file (or associated split paths): {}",
            store_path.display()
        );

        let store_len = config.size.expect("disk store size not configured");
        for config in &configs {
            ensure!(
                LevelCacheStore::<DefaultPieceDomain, std::fs::File>::is_consistent(
                    store_len,
                    Tree::Arity::to_usize(),
                    &config,
                )?,
                "Store is inconsistent: {:?}",
                StoreConfig::data_path(&config.path, &config.id)
            );
        }
    } else {
        ensure!(
            LevelCacheStore::<DefaultPieceDomain, std::fs::File>::is_consistent(
                config.size.expect("disk store size not configured"),
                Tree::Arity::to_usize(),
                &config,
            )?,
            "Store is inconsistent: {:?}",
            store_path
        );
    }

    Ok(())
}
