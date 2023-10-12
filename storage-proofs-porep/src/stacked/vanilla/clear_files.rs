use std::{fs, path::Path};

use anyhow::{Context, Result};
use log::trace;
use merkletree::store::StoreConfig;
use storage_proofs_core::cache_key::{CacheKey, LABEL_LAYER_KEY};

use crate::stacked::vanilla::{
    SYNTHETIC_POREP_VANILLA_PROOFS_EXT, SYNTHETIC_POREP_VANILLA_PROOFS_KEY,
};

/// Removes all files that match the given glob pattern.
fn remove_files_with_glob(glob_path: &Path) -> Result<()> {
    let globs = glob::glob(glob_path.to_str().expect("Path must be valid UTF-8"))
        .expect("Glob pattern must be valid");
    for maybe_path in globs {
        let path = maybe_path?;
        fs::remove_file(&path).with_context(|| format!("Failed to delete {:?}", &path))?
    }
    Ok(())
}

/// Discards all persisted merkle and layer data that is not needed for PoSt.
pub fn clear_cache_dir(cache_path: &Path) -> Result<()> {
    let tree_d_path = StoreConfig::data_path(cache_path, &CacheKey::CommDTree.to_string());
    if tree_d_path.exists() {
        fs::remove_file(&tree_d_path)
            .with_context(|| format!("Failed to delete {:?}", &tree_d_path))?;
        trace!("tree d deleted");
    }

    // TreeC might be split into several sub-tree. They have the same file name, but a number
    // attached separated by a dash. Hence add a glob after the identifier.
    let tree_c_glob = StoreConfig::data_path(cache_path, &format!("{}*", CacheKey::CommCTree));
    remove_files_with_glob(&tree_c_glob)?;
    trace!("tree c deleted");

    let labels_glob = StoreConfig::data_path(cache_path, &format!("{}*", LABEL_LAYER_KEY));
    remove_files_with_glob(&labels_glob)?;
    trace!("layers deleted");

    Ok(())
}

/// Ensure that any persisted vanilla proofs generated from synthetic porep are discarded.
pub fn clear_synthetic_proofs(cache_path: &Path) -> Result<()> {
    let synth_proofs_path = cache_path.join(format!(
        "{}.{}",
        SYNTHETIC_POREP_VANILLA_PROOFS_KEY, SYNTHETIC_POREP_VANILLA_PROOFS_EXT
    ));
    if synth_proofs_path.exists() {
        trace!("removing synthetic proofs at {:?}", synth_proofs_path);
        fs::remove_file(&synth_proofs_path)
            .with_context(|| format!("Failed to delete {:?}", &synth_proofs_path))
    } else {
        trace!(
            "persisted synthetic proofs do not exist at {:?}",
            synth_proofs_path
        );

        Ok(())
    }
}
