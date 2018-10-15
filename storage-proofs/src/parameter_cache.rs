use bellman::groth16::Parameters;
use bellman::{groth16, Circuit};
use error::Result;
use failure::Error;
use fs2::FileExt;
use itertools::Itertools;
use rand::XorShiftRng;
use sapling_crypto::jubjub::JubjubEngine;
use sha2::{Digest, Sha256};

use std::env;
use std::fs::{self, create_dir_all};
use std::path::{Path, PathBuf};

/// Bump this when circuits change to invalidate the cache.
pub const VERSION: usize = 2;

pub const PARAMETER_CACHE_DIR: &str = "/tmp/filecoin-proof-parameters/";

fn parameter_cache_dir_name() -> String {
    match env::var("FILECOIN_PARAMETER_CACHE") {
        Ok(dir) => dir,
        Err(_) => String::from(PARAMETER_CACHE_DIR),
    }
}

fn parameter_cache_dir() -> PathBuf {
    Path::new(&parameter_cache_dir_name()).to_path_buf()
}

pub fn parameter_cache_path(filename: &str) -> PathBuf {
    let name = parameter_cache_dir_name();
    let dir = Path::new(&name);
    dir.join(format!("v{}-{}", VERSION, filename))
}

pub trait ParameterSetIdentifier {
    fn parameter_set_identifier(&self) -> String;
}

pub trait CacheableParameters<E: JubjubEngine, C: Circuit<E>, PP>
where
    PP: ParameterSetIdentifier,
{
    fn cache_prefix() -> String;
    fn cache_identifier(pub_params: &PP) -> Option<String> {
        let param_identifier = pub_params.parameter_set_identifier();
        info!(target: "params", "parameter set identifier for cache: {}", param_identifier);
        let mut hasher = Sha256::default();
        hasher.input(&param_identifier.into_bytes());
        let circuit_hash = hasher.result();
        Some(format!(
            "{}-{:02x}",
            Self::cache_prefix(),
            circuit_hash.iter().format("")
        ))
    }

    fn get_groth_params(
        circuit: C,
        pub_params: &PP,
        rng: &mut XorShiftRng,
    ) -> Result<groth16::Parameters<E>> {
        let generate = || {
            info!(target: "params", "Actually generating groth params.");
            groth16::generate_random_parameters::<E, _, _>(circuit, rng)
        };

        match Self::cache_identifier(pub_params) {
            Some(id) => {
                let cache_dir = parameter_cache_dir();
                create_dir_all(cache_dir)?;
                let cache_path = parameter_cache_path(&id);
                info!(target: "params", "checking cache_path: {:?}", cache_path);

                read_cached_params(&cache_path).or_else(|_| {
                    ensure_parent(&cache_path)?;

                    let mut f = fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .open(&cache_path)?;
                    f.lock_exclusive()?;

                    let p = generate()?;

                    p.write(&mut f)?;
                    info!(target: "params", "wrote parameters to cache {:?} ", f);
                    Ok(p)
                })
            }
            None => Ok(generate()?),
        }
    }
}

fn ensure_parent(path: &PathBuf) -> Result<()> {
    match path.parent() {
        Some(dir) => {
            create_dir_all(dir)?;
            Ok(())
        }
        None => Ok(()),
    }
}

pub fn read_cached_params<E: JubjubEngine>(cache_path: &PathBuf) -> Result<groth16::Parameters<E>> {
    ensure_parent(cache_path)?;

    let f = fs::OpenOptions::new().read(true).open(&cache_path)?;
    f.lock_exclusive()?;
    info!(target: "params", "reading groth params from cache: {:?}", cache_path);

    Parameters::read(&f, false).map_err(Error::from)
}

pub fn write_params_to_cache<E: JubjubEngine>(
    p: groth16::Parameters<E>,
    cache_path: &PathBuf,
) -> Result<groth16::Parameters<E>> {
    ensure_parent(cache_path)?;

    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&cache_path)?;
    f.lock_exclusive()?;

    p.write(&mut f)?;
    info!(target: "params", "wrote parameters to cache {:?} ", f);
    Ok(p)
}
