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
    pub maximize_caching: bool,
    pub pedersen_hash_exp_window_size: u32,
    pub use_gpu_column_builder: bool,
    pub max_gpu_column_batch_size: u32,
    pub max_gpu_tree_batch_size: u32,
    pub rows_to_discard: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            maximize_caching: false,
            pedersen_hash_exp_window_size: 16,
            use_gpu_column_builder: false,
            max_gpu_column_batch_size: 400_000,
            max_gpu_tree_batch_size: 700_000,
            rows_to_discard: 0,
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
