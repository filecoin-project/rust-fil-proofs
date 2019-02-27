use crate::error::*;
use bellman::groth16::Parameters;
use bellman::{groth16, Circuit};
use fs2::FileExt;
use itertools::Itertools;
use rand::{SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::JubjubEngine;
use sha2::{Digest, Sha256};

use std::env;
use std::fs::{self, create_dir_all, File};
use std::io::{self, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::SP_LOG;

/// Bump this when circuits change to invalidate the cache.
pub const VERSION: usize = 10;

pub const PARAMETER_CACHE_DIR: &str = "/tmp/filecoin-proof-parameters/";

/// If this changes, parameters generated under different conditions may vary. Don't change it.
pub const PARAMETER_RNG_SEED: [u32; 4] = [0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654];

#[derive(Debug)]
struct LockedFile(File);

// TODO: use in memory lock as well, as file locks do not guarantee exclusive access acros OSes.

impl LockedFile {
    pub fn open_exclusive_read<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        let f = fs::OpenOptions::new().read(true).open(p)?;
        f.lock_exclusive()?;

        Ok(LockedFile(f))
    }

    pub fn open_exclusive<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        let f = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(p)?;
        f.lock_exclusive()?;

        Ok(LockedFile(f))
    }
}

impl io::Write for LockedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl io::Read for LockedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl io::Seek for LockedFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl Drop for LockedFile {
    fn drop(&mut self) {
        self.0
            .unlock()
            .unwrap_or_else(|e| panic!("{}: failed to {:?} unlock file safely", e, &self.0));
    }
}

pub fn parameter_cache_dir_name() -> String {
    match env::var("FILECOIN_PARAMETER_CACHE") {
        Ok(dir) => dir,
        Err(_) => String::from(PARAMETER_CACHE_DIR),
    }
}

pub fn parameter_cache_dir() -> PathBuf {
    Path::new(&parameter_cache_dir_name()).to_path_buf()
}

pub fn parameter_cache_path(filename: &str) -> PathBuf {
    let name = parameter_cache_dir_name();
    let dir = Path::new(&name);
    dir.join(format!("v{}-{}", VERSION, filename))
}

pub trait ParameterSetIdentifier: Clone {
    fn parameter_set_identifier(&self) -> String;
}

pub trait CacheableParameters<E: JubjubEngine, C: Circuit<E>, PP>
where
    PP: ParameterSetIdentifier,
{
    fn cache_prefix() -> String;
    fn cache_identifier(pub_params: &PP) -> String {
        let param_identifier = pub_params.parameter_set_identifier();
        info!(SP_LOG, "parameter set identifier for cache: {}", param_identifier; "target" => "params");
        let mut hasher = Sha256::default();
        hasher.input(&param_identifier.into_bytes());
        let circuit_hash = hasher.result();
        format!(
            "{}-{:02x}",
            Self::cache_prefix(),
            circuit_hash.iter().format("")
        )
    }

    fn get_groth_params(circuit: C, pub_params: &PP) -> Result<groth16::Parameters<E>> {
        // Always seed the rng identically so parameter generation will be deterministic.

        let id = Self::cache_identifier(pub_params);

        let generate = || {
            let rng = &mut XorShiftRng::from_seed(PARAMETER_RNG_SEED);
            info!(SP_LOG, "Actually generating groth params."; "target" => "params", "id" => &id);
            let start = Instant::now();
            let parameters = groth16::generate_random_parameters::<E, _, _>(circuit, rng);
            let generation_time = start.elapsed();
            info!(SP_LOG, "groth_parameter_generation_time: {:?}", generation_time; "target" => "stats", "id" => &id);
            parameters
        };

        let cache_dir = parameter_cache_dir();
        create_dir_all(cache_dir)?;
        let cache_path = parameter_cache_path(&id);
        info!(SP_LOG, "checking cache_path: {:?}", cache_path; "target" => "params", "id" => &id);

        read_cached_params(&cache_path).or_else(|_| {
            ensure_parent(&cache_path)?;

            let mut f = LockedFile::open_exclusive(&cache_path)?;
            let p = generate()?;

            p.write(&mut f)?;
            info!(SP_LOG, "wrote parameters to cache {:?} ", f; "target" => "params", "id" => &id);

            let bytes = f.seek(SeekFrom::End(0))?;
            info!(SP_LOG, "groth_parameter_bytes: {}", bytes; "target" => "stats", "id" => &id);

            Ok(p)
        })
    }

    fn get_verifying_key(circuit: C, pub_params: &PP) -> Result<groth16::VerifyingKey<E>> {
        let id = Self::cache_identifier(pub_params);
        let vk_id = format!("{}.vk", id);

        let generate = || -> Result<groth16::VerifyingKey<E>> {
            let groth_params = Self::get_groth_params(circuit, pub_params)?;
            info!(SP_LOG, "Getting verifying key."; "target" => "verifying_key", "id" => &vk_id);
            Ok(groth_params.vk)
        };

        let cache_dir = parameter_cache_dir();
        create_dir_all(cache_dir)?;
        let cache_path = parameter_cache_path(&vk_id);
        info!(SP_LOG, "checking cache_path: {:?}", cache_path; "target" => "verifying_key", "id" => &vk_id);

        read_cached_verifying_key(&cache_path).or_else(|_| {
            ensure_parent(&cache_path)?;

            let mut f = LockedFile::open_exclusive(&cache_path)?;
            let p = generate()?;

            p.write(&mut f)?;
            info!(SP_LOG, "wrote verifying key to cache {:?} ", f; "target" => "verifying_key", "id" => &vk_id);

            let bytes = f.seek(SeekFrom::End(0))?;
            info!(SP_LOG, "verifying_key_bytes: {}", bytes; "target" => "stats", "id" => &vk_id);

            Ok(p)
        })
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

    let mut f = LockedFile::open_exclusive_read(&cache_path)?;
    info!(SP_LOG, "reading groth params from cache: {:?}", cache_path; "target" => "params");

    // TODO: Should we be passing true, to perform a checked read?
    let params = Parameters::read(&mut f, false).map_err(Error::from)?;

    let bytes = f.seek(SeekFrom::End(0))?;
    info!(SP_LOG, "groth_parameter_bytes: {}", bytes; "target" => "stats");

    Ok(params)
}

pub fn read_cached_verifying_key<E: JubjubEngine>(
    cache_path: &PathBuf,
) -> Result<groth16::VerifyingKey<E>> {
    ensure_parent(cache_path)?;

    let mut f = LockedFile::open_exclusive_read(&cache_path)?;
    info!(SP_LOG, "reading verifying key from cache: {:?}", cache_path; "target" => "verifying_key");

    let key = groth16::VerifyingKey::read(&mut f).map_err(Error::from)?;
    let bytes = f.seek(SeekFrom::End(0))?;
    info!(SP_LOG, "verifying_key_bytes: {}", bytes; "target" => "stats");

    Ok(key)
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
    f.unlock()?;

    info!(SP_LOG, "wrote parameters to cache {:?} ", f; "target" => "params");
    Ok(p)
}
