use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{stdin, stdout, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use blake2b_simd::State as Blake2b;
use serde::{Deserialize, Serialize};
use storage_proofs::parameter_cache::{
    parameter_cache_dir, CacheEntryMetadata, PARAMETER_METADATA_EXT,
};

const ERROR_STRING: &str = "invalid string";

pub type ParameterMap = BTreeMap<String, ParameterData>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ParameterData {
    pub cid: String,
    pub digest: String,
    pub sector_size: u64,
}

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

    std::io::copy(&mut file, &mut hasher)?;

    Ok(hasher.finalize().to_hex()[..32].into())
}

// Prompts the user to approve/reject the message
pub fn choose(message: &str) -> bool {
    loop {
        print!("[y/n] {}: ", message);

        let _ = stdout().flush();
        let mut s = String::new();
        stdin().read_line(&mut s).expect(ERROR_STRING);

        match s.trim().to_uppercase().as_str() {
            "Y" => return true,
            "N" => return false,
            _ => {}
        }
    }
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

/// Builds a map from filename (in cache) to metadata.
pub fn parameter_id_to_metadata_map<S: AsRef<str>>(
    filenames: &[S],
) -> Result<BTreeMap<String, CacheEntryMetadata>> {
    let mut map: BTreeMap<String, CacheEntryMetadata> = Default::default();

    for filename in filenames {
        if has_extension(PathBuf::from(filename.as_ref()), PARAMETER_METADATA_EXT) {
            let file_path = get_full_path_for_file_within_cache(filename.as_ref());
            let file = File::open(&file_path)
                .with_context(|| format!("could not open path={:?}", file_path))?;

            let meta = serde_json::from_reader(file)?;

            let p_id = filename_to_parameter_id(PathBuf::from(filename.as_ref()))
                .context("could not map filename to parameter id")?;

            map.insert(p_id, meta);
        }
    }

    Ok(map)
}

/// Prompts the user to approve/reject the filename
pub fn choose_from<S: AsRef<str>>(
    filenames: &[S],
    lookup: impl Fn(&str) -> Option<u64>,
) -> Result<Vec<String>> {
    let mut chosen_filenames: Vec<String> = vec![];

    for filename in filenames.iter() {
        let sector_size = lookup(filename.as_ref())
            .with_context(|| format!("no sector size found for filename {}", filename.as_ref()))?;

        let msg = format!("(sector size: {}B) {}", sector_size, filename.as_ref());

        if choose(&msg) {
            chosen_filenames.push(filename.as_ref().to_string())
        }
    }

    Ok(chosen_filenames)
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
