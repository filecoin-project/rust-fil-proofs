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
    pub generate_merkle_trees_in_parallel: bool,
    pub pedersen_hash_exp_window_size: u32,
    // Generating MTs in parallel optimizes for speed while generating them
    // in sequence (`false`) optimizes for memory.
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            maximize_caching: false,
            merkle_tree_path: "/tmp/merkle-trees".into(),
            num_proving_threads: 1,
            replicated_trees_dir: "".into(),
            generate_merkle_trees_in_parallel: true,
            pedersen_hash_exp_window_size: 16,
        }
    }
}

impl Settings {
    fn new() -> Result<Settings, ConfigError> {
        let mut s = Config::new();

        s.merge(File::with_name(SETTINGS_PATH).required(false))?;
        s.merge(Environment::with_prefix("FIL_PROOFS"))?;

        let settings: Result<Settings, ConfigError> = s.try_into();

        #[cfg(not(feature = "disk-trees"))]
        {
            if settings.is_ok() && !settings.as_ref().unwrap().generate_merkle_trees_in_parallel {
                warn!("Setting GENERATE_MERKLE_TREES_IN_PARALLEL to false (sequiental generation) \ndoesn't add any value if the `disk-trees` feature is not set (no offload possible)");
            }
        }

        settings
    }
}
