use std::sync::Mutex;

use config::{Config, ConfigError, Environment, File};

lazy_static! {
    pub static ref SETTINGS: Mutex<Settings> =
        Mutex::new(Settings::new().expect("invalid configuration"));
}

const SETTINGS_PATH: &str = "./rust-fil-proofs.config.toml";

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub maximize_caching: bool,
    pub merkle_tree_path: String,
    pub num_proving_threads: usize,
    pub replicated_trees_dir: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            maximize_caching: false,
            merkle_tree_path: "/tmp/merkle-trees".into(),
            num_proving_threads: 1,
            replicated_trees_dir: "".into(),
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
