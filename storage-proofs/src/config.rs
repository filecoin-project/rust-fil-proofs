use failure::{err_msg, Error};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::prelude::Read;
use std::path::Path;
use std::sync::Mutex;

type Result<T> = ::std::result::Result<T, Error>;
type Config = HashMap<String, bool>;

const CONFIG_PATH: &str = "./rust-fil-proofs.config.toml";

const DEFAULT_CONFIG: &[(&str, bool)] = &[("MAXIMIZE_CACHING", false)];

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
        .map(|&(k, v)| (k.to_string(), v))
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
        let var = env::var(&key);

        if var.is_ok() {
            env_config.insert(key.to_string(), var.unwrap() != "");
        }
    }

    Ok(env_config)
}

pub fn set_config(key: &str, value: bool) -> Result<()> {
    let config = &mut (*CONFIG).lock().unwrap();
    config.insert(key.to_string(), value);

    Ok(())
}

pub fn get_config(key: &str) -> Result<bool> {
    let config = (*CONFIG).lock().unwrap();

    match config.get(key) {
        Some(&value) => Ok(value),
        None => Err(err_msg("key not found in config")),
    }
}

pub fn debug_config() {
    let config = (*CONFIG).lock().unwrap();

    for (key, value) in config.iter() {
        println!("{}: {}", key, value);
    }
}
