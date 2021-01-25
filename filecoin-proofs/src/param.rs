use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake2b_simd::State as Blake2b;
use storage_proofs_core::parameter_cache::{
    parameter_cache_dir, CacheEntryMetadata, PARAMETER_METADATA_EXT,
};

// Produces an absolute path to a file within the cache
pub fn get_full_path_for_file_within_cache(filename: &str) -> PathBuf {
    let mut path = parameter_cache_dir();
    path.push(filename);
    path
}

// Produces a BLAKE2b checksum for a file within the cache
pub fn get_digest_for_file_within_cache(filename: &str) -> Result<String> {
    let path = get_full_path_for_file_within_cache(filename);
    let mut file = File::open(&path).with_context(|| format!("could not open path={:?}", path))?;
    let mut hasher = Blake2b::new();

    io::copy(&mut file, &mut hasher)?;

    Ok(hasher.finalize().to_hex()[..32].into())
}

// Predicate which matches the provided extension against the given filename
pub fn has_extension<S: AsRef<str>, P: AsRef<Path>>(filename: P, ext: S) -> bool {
    filename
        .as_ref()
        .extension()
        .and_then(OsStr::to_str)
        .map(|s| s == ext.as_ref())
        .unwrap_or(false)
}

// Adds a file extension to the given filename
pub fn add_extension(filename: &str, ext: &str) -> String {
    format!("{}.{}", filename, ext)
}

/// Builds a map from a parameter_id (file in cache) to metadata.
pub fn parameter_id_to_metadata_map(
    parameter_ids: &[String],
) -> Result<BTreeMap<String, CacheEntryMetadata>> {
    let mut map: BTreeMap<String, CacheEntryMetadata> = Default::default();

    for parameter_id in parameter_ids {
        let filename = add_extension(parameter_id, PARAMETER_METADATA_EXT);
        let file_path = get_full_path_for_file_within_cache(&filename);
        let file = File::open(&file_path)
            .with_context(|| format!("could not open path={:?}", file_path))?;

        let meta = serde_json::from_reader(file)?;

        map.insert(parameter_id.to_string(), meta);
    }

    Ok(map)
}

/// Maps the name of a file in the cache to its parameter id. For example,
/// ABCDEF.vk corresponds to parameter id ABCDEF.
pub fn filename_to_parameter_id<'a, P: AsRef<Path> + 'a>(filename: P) -> Option<String> {
    filename
        .as_ref()
        .file_stem()
        .and_then(OsStr::to_str)
        .map(ToString::to_string)
}
