use std::env;

use config::{Config, ConfigError, Environment, File};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

lazy_static! {
    pub static ref SETTINGS: Settings = Settings::new().expect("invalid configuration");
}

const SETTINGS_PATH: &str = "./rust-fil-proofs.config.toml";
const PREFIX: &str = "FIL_PROOFS";

#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub verify_cache: bool,
    pub verify_production_params: bool,
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
    pub use_multicore_sdr: bool,
    pub multicore_sdr_producers: usize,
    pub multicore_sdr_producer_stride: u64,
    pub multicore_sdr_lookahead: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            verify_cache: false,
            verify_production_params: false,
            use_gpu_column_builder: false,
            max_gpu_column_batch_size: 400_000,
            column_write_batch_size: 262_144,
            use_gpu_tree_builder: false,
            max_gpu_tree_batch_size: 700_000,
            rows_to_discard: 2,
            sdr_parents_cache_size: 2_048,
            window_post_synthesis_num_cpus: num_cpus::get() as u32,
            // `parameter_cache` does not use the cache() mechanism because it is now used
            // for durable, canonical Groth parameters and verifying keys.
            // The name is retained for backwards compatibility.
            parameter_cache: "/var/tmp/filecoin-proof-parameters/".to_string(),
            parent_cache: cache("filecoin-parents"),
            use_multicore_sdr: false,
            multicore_sdr_producers: 3,
            multicore_sdr_producer_stride: 128,
            multicore_sdr_lookahead: 800,
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

/// Sets an environment variable to a value if it isn't properly set yet.
fn set_env_var_if_unset(env_var: &str, value: &str) {
    if env::var(env_var).is_err() {
        env::set_var(env_var, value);
    }
}

/// Set the GPU framework for the dependencies.
///
/// If a GPU framework, CUDA and OpenCL is selected, it needs to be communicated some of the
/// dependnecies. This is done via environment variables.
///
/// If one of those environment variables is already set, it won't be overridden.
fn set_gpu_framework() {
    if let Ok(framework) = env::var(format!("{}_GPU_FRAMEWORK", PREFIX)) {
        set_env_var_if_unset("BELLMAN_GPU_FRAMEWORK", &framework);
        set_env_var_if_unset("NEPTUNE_GPU_FRAMEWORK", &framework);
    }
}

/// Set CUDA nvcc compile flags (if set) for the dependencies.
///
/// If one of those environment variables is already set, it won't be overridden.
fn set_cuda_nvcc_args() {
    if let Ok(nvcc_args) = env::var(format!("{}_CUDA_NVCC_ARGS", PREFIX)) {
        set_env_var_if_unset("BELLMAN_CUDA_NVCC_ARGS", &nvcc_args);
        set_env_var_if_unset("NEPTUNE_CUDA_NVCC_ARGS", &nvcc_args);
    }
}

impl Settings {
    fn new() -> Result<Settings, ConfigError> {
        set_gpu_framework();
        set_cuda_nvcc_args();

        let mut s = Config::new();

        s.merge(File::with_name(SETTINGS_PATH).required(false))?;
        s.merge(Environment::with_prefix(PREFIX))?;

        s.try_into()
    }
}
