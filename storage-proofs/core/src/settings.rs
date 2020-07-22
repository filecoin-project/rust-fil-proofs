use std::env;
use std::sync::Mutex;

use config::{Config, ConfigError, Environment, File};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref SETTINGS: Mutex<Settings> =
        Mutex::new(Settings::new().expect("invalid configuration"));
}

const SETTINGS_PATH: &str = "./rust-fil-proofs.config.toml";
const PREFIX: &str = "FIL_PROOFS";

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub maximize_caching: bool,
    pub pedersen_hash_exp_window_size: u32,
    pub use_gpu_column_builder: bool,
    pub max_gpu_column_batch_size: u32,
    pub column_write_batch_size: u32,
    pub use_gpu_tree_builder: bool,
    pub max_gpu_tree_batch_size: u32,
    pub rows_to_discard: u32,
    pub sdr_parents_cache_size: u32,
    pub window_post_synthesis_num_cpus: u32,
    pub parameter_cache: String,
    pub parent_cache: String,
    pub use_gpu_nse: bool
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            maximize_caching: true,
            pedersen_hash_exp_window_size: 16,
            use_gpu_column_builder: false,
            max_gpu_column_batch_size: 400_000,
            column_write_batch_size: 262_144,
            use_gpu_tree_builder: false,
            max_gpu_tree_batch_size: 700_000,
            rows_to_discard: 2,
            sdr_parents_cache_size: 2_048,
            window_post_synthesis_num_cpus: num_cpus::get() as u32,
            use_gpu_nse: false,
            // `parameter_cache` does not use the cache() mechanism because it is now used
            // for durable, canonical Groth parameters and verifying keys.
            // The name is retained for backwards compatibility.
            parameter_cache: "/var/tmp/filecoin-proof-parameters/".to_string(),
            parent_cache: cache("filecoin-parents"),
        }
    }
}

/// All cache files and directories paths should be constructed using this function,
/// which its base directory from the FIL_PROOFS_CACHE_DIR env var, and defaults to /var/tmp.
/// Note that FIL_PROOFS_CACHE_DIR is not a first class setting and can only be set by env var.
fn cache(s: &str) -> String {
    let cache_var = format!("{}_CACHE_DIR", PREFIX);
    let mut cache_name = env::var(cache_var).unwrap_or_else(|_| "/var/tmp/".to_string());
    cache_name.push_str(s);
    cache_name
}

impl Settings {
    fn new() -> Result<Settings, ConfigError> {
        let mut s = Config::new();

        s.merge(File::with_name(SETTINGS_PATH).required(false))?;
        s.merge(Environment::with_prefix(PREFIX))?;

        s.try_into()
    }
}
