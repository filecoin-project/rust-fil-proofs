use std::sync::Mutex;

use config::{Config, ConfigError, Environment, File};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref SETTINGS: Mutex<Settings> =
        Mutex::new(Settings::new().expect("invalid configuration"));
}

const SETTINGS_PATH: &str = "./rust-fil-proofs.config.toml";

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Caches the DRG and Expander Graph nodes in memory.
    pub cache_graph: bool,
    pub pedersen_hash_exp_window_size: u32,
    /// If true, tries to offload as much as possible to disk, during replication.
    pub replicate_on_disk: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            cache_graph: true,
            pedersen_hash_exp_window_size: 16,
            replicate_on_disk: false,
        }
    }
}

impl Settings {
    fn new() -> Result<Settings, ConfigError> {
        let mut s = Config::new();

        s.merge(File::with_name(SETTINGS_PATH).required(false))?;
        s.merge(Environment::with_prefix("FIL_PROOFS"))?;

        s.try_into()
    }
}
