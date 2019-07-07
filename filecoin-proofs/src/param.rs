use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{stdin, stdout, BufReader, Write};
use std::path::{Path, PathBuf};

use blake2b_simd::State as Blake2b;
use failure::Error;
use serde::{Deserialize, Serialize};

use storage_proofs::parameter_cache::parameter_cache_dir;

const ERROR_STRING: &str = "invalid string";

pub type Result<T> = ::std::result::Result<T, Error>;
pub type ParameterMap = BTreeMap<String, ParameterData>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ParameterData {
    pub cid: String,
    pub digest: String,
    pub sector_size: Option<u64>,
}

// Deserializes bytes from the provided path into a ParameterMap
pub fn read_parameter_map_from_disk<P: AsRef<Path>>(source_path: P) -> Result<ParameterMap> {
    let file = File::open(source_path)?;
    let reader = BufReader::new(file);
    let parameter_map = serde_json::from_reader(reader)?;

    Ok(parameter_map)
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
    let mut file = File::open(path)?;
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

// Prompts the user to approve/reject the messages
pub fn choose_from(messages: Vec<String>) -> Result<Vec<String>> {
    Ok(messages.into_iter().filter(|i| choose(i)).collect())
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
