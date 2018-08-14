use bellman::groth16::Parameters;
use bellman::{groth16, Circuit};
use error::Result;
use itertools::Itertools;
use rand::XorShiftRng;
use sapling_crypto::jubjub::JubjubEngine;
use sha2::{Digest, Sha256};
use std::fs::{create_dir_all, File};
use std::path::Path;

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
                    let mut f = File::open(&cache_path).expect("failed to read cache");
                    Parameters::read(&f, false).expect("failed to read cached params")
                } else {
                    let p = generate()?;
                    let mut f = File::create(&cache_path).expect("failed to open cache file");
                    p.write(&mut f)?;
                    info!(target: "params", "wrote parameters to cache {:?} ", f);
                    p
                };

                Ok(groth_params)
            }
            None => Ok(generate()?),
        }
    }
}
