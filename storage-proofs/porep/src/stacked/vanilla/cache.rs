use std::env;
use std::path::{Path, PathBuf};

pub const SDR_CACHE_ENV_VAR: &str = "FIL_PROOFS_SDR_CACHE";
pub const PARAMETER_CACHE_DIR: &str = "/var/tmp/filecoin-proof-sdr-cache/";

pub fn dir_name() -> PathBuf {
    env::var(SDR_CACHE_ENV_VAR)
        .map(PathBuf::from)
        .unwrap_or(PathBuf::from(PARAMETER_CACHE_DIR))
}

pub fn file_path<P: AsRef<Path>>(name: P) -> PathBuf {
    dir_name().join(name)
}
