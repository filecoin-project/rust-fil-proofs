#[macro_use]
extern crate lazy_static;

extern crate failure;
extern crate toml;

use failure::{Error, err_msg};
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::Read;
use std::sync::Mutex;

type Result<T> = ::std::result::Result<T, Error>;
type Config = HashMap<String, bool>;

const CONFIG_PATH: &str = "./rust-fil-proofs.config.toml";

lazy_static! {
    pub static ref CONFIG: Mutex<Config> = Mutex::new(load_config_toml(CONFIG_PATH).unwrap());
}

pub fn load_config_toml(path: &str) -> Result<Config> {
    let mut f = File::open(path)?;
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    let config: HashMap<String, bool> = toml::from_str(&contents)?;

    for (key, &value) in config.iter() {
        set_config(key, value)?;
    }

    Ok(config)
}

pub fn set_config(key: &str, value: bool) -> Result<()> {
    let config = &mut (*CONFIG).lock().unwrap();
    config.insert(key.to_string(), value);

    Ok(())
}

pub fn get_config(key: &str) -> Result<bool> {
    let config = &mut (*CONFIG).lock().unwrap();

    match config.get(key) {
        Some(&value) => Ok(value),
        None => Err(err_msg("key not found in config")),
    }
}
