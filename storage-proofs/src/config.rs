use failure::{err_msg, Error};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::prelude::Read;
use std::path::Path;
use std::sync::Mutex;

type Result<T> = ::std::result::Result<T, Error>;

const CONFIG_PATH: &str = "./rust-fil-proofs.config.toml";

type Config = HashMap<String, String>;

const DEFAULT_CONFIG: &[(&str, &str)] = &[
    ("MAXIMIZE_CACHING", "false"),
    // Directory where we will store replicated MTs backed by `mmap` with
    // file-mapping (`crate::merkle::DiskMmapStore`). An empty string signals
    // to create temporary files (which will be erased after execution).
    ("REPLICATED_TREES_DIR", ""),
];

lazy_static! {
    pub static ref CONFIG: Mutex<Config> = Mutex::new(initialize_config().unwrap());
}

pub fn initialize_config() -> Result<Config> {
    let mut config: Config = Default::default();

    config.extend(load_config_from_defaults()?);
    config.extend(load_config_from_toml(CONFIG_PATH)?);
    config.extend(load_config_from_env()?);

    Ok(config)
}

pub fn load_config_from_defaults() -> Result<Config> {
    Ok(DEFAULT_CONFIG
        .iter()
        .map(|&(k, v)| (k.to_string(), v.to_string()))
        .collect())
}

pub fn load_config_from_toml(path: &str) -> Result<Config> {
    let path = Path::new(path);

    if path.exists() {
        let mut f = File::open(path)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(toml::from_str(&contents)?)
    } else {
        Ok(Default::default())
    }
}

pub fn load_config_from_env() -> Result<Config> {
    let mut env_config: Config = Default::default();

    for key in DEFAULT_CONFIG.iter().map(|(k, _)| k) {
        if let Ok(var) = env::var(&key) {
            env_config.insert(key.to_string(), var);
        }
    }

    Ok(env_config)
}

pub fn set_config(key: &str, value: &str) -> Result<()> {
    let config = &mut (*CONFIG).lock().unwrap();
    config.insert(key.to_string(), value.to_string());

    Ok(())
}

pub fn get_config(key: &str) -> Result<String> {
    let config = (*CONFIG).lock().unwrap();

    match config.get(key).as_ref() {
        Some(value) => Ok(value.to_string()),
        None => Err(err_msg("key not found in config")),
    }
}

pub fn get_config_bool(key: &str) -> Result<bool> {
    match get_config(key)?.to_lowercase().as_ref() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" | "" => Ok(false),
        _ => Err(err_msg("cannot cast as bool")),
    }
}

pub fn debug_config() {
    let config = (*CONFIG).lock().unwrap();

    for (key, value) in config.iter() {
        println!("{}: {}", key, value);
    }
}
