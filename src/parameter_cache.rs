use bellman::groth16::Parameters;
use bellman::{groth16, Circuit};
use error::Result;
use fs2::FileExt;
use itertools::Itertools;
use rand::XorShiftRng;
use sapling_crypto::jubjub::JubjubEngine;
use sha2::{Digest, Sha256};
use std::fs::{self, create_dir_all};
use std::path::{Path, PathBuf};

const PARAMETER_CACHE_DIR: &str = "/tmp/filecoin-proof-parameters/";

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
                let cache_dir = PARAMETER_CACHE_DIR;
                create_dir_all(cache_dir)?;
                let cache_path = Path::new(cache_dir).join(id);
                info!(target: "params", "checking cache_path: {:?}", cache_path);
                let groth_params: Parameters<E> = if cache_path.exists() {
                    info!(target: "params", "reading groth params from cache: {:?}", cache_path);
                    read_cached_params(&cache_path)?
                } else {
                    let p = generate()?;
                    write_params_to_cache(p, &cache_path)?
                };

                Ok(groth_params)
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

    Ok(Parameters::read(&f, false).expect("failed to read cached params"))
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
