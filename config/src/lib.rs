#[macro_use]
extern crate lazy_static;

extern crate failure;
extern crate toml;

use failure::{Error, err_msg};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::io::prelude::Read;
use std::sync::Mutex;
use std::env;

type Result<T> = ::std::result::Result<T, Error>;
type Config = HashMap<String, bool>;

const DEFAULT_CONFIG_PATH: &str = "./rust-fil-proofs.default.config.toml";
const CONFIG_PATH: &str = "./rust-fil-proofs.config.toml";

lazy_static! {
    pub static ref CONFIG: Mutex<Config> = Mutex::new(initialize_config().unwrap());
}

pub fn initialize_config() -> Result<Config> {
    let default_config: Config = load_config_from_toml(DEFAULT_CONFIG_PATH)?;
    let toml_config: Config = load_config_from_toml(CONFIG_PATH)?;
    let env_config: Config = load_config_from_env(&default_config)?;

    Ok(default_config.into_iter().chain(toml_config).chain(env_config).collect())
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

pub fn load_config_from_env(config: &Config) -> Result<Config> {
    let mut env_config: Config = Default::default();

    for key in config.keys() {
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
