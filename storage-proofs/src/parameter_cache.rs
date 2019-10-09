use crate::error::*;
use bellperson::groth16::Parameters;
use bellperson::{groth16, Circuit};
use fil_sapling_crypto::jubjub::JubjubEngine;
use fs2::FileExt;
use itertools::Itertools;
use rand::{SeedableRng, XorShiftRng};
use sha2::{Digest, Sha256};

use std::env;
use std::fs::{self, create_dir_all, File};
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::error::Error::Unclassified;

/// Bump this when circuits change to invalidate the cache.
pub const VERSION: usize = 13;

pub const PARAMETER_CACHE_ENV_VAR: &str = "FIL_PROOFS_PARAMETER_CACHE";

pub const PARAMETER_CACHE_DIR: &str = "/var/tmp/filecoin-proof-parameters/";

/// If this changes, parameters generated under different conditions may vary. Don't change it.
pub const PARAMETER_RNG_SEED: [u32; 4] = [0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654];

pub const GROTH_PARAMETER_EXT: &str = "params";

pub const PARAMETER_METADATA_EXT: &str = "meta";

pub const VERIFYING_KEY_EXT: &str = "vk";

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

fn parameter_cache_dir_name() -> String {
    match env::var(PARAMETER_CACHE_ENV_VAR) {
        Ok(dir) => dir,
        Err(_) => String::from(PARAMETER_CACHE_DIR),
    }
}

pub fn parameter_cache_dir() -> PathBuf {
    Path::new(&parameter_cache_dir_name()).to_path_buf()
}

pub fn parameter_cache_params_path(parameter_set_identifier: &str) -> PathBuf {
    let dir = Path::new(&parameter_cache_dir_name()).to_path_buf();
    dir.join(format!(
        "v{}-{}.{}",
        VERSION, parameter_set_identifier, GROTH_PARAMETER_EXT
    ))
}

pub fn parameter_cache_metadata_path(parameter_set_identifier: &str) -> PathBuf {
    let dir = Path::new(&parameter_cache_dir_name()).to_path_buf();
    dir.join(format!(
        "v{}-{}.{}",
        VERSION, parameter_set_identifier, PARAMETER_METADATA_EXT
    ))
}

pub fn parameter_cache_verifying_key_path(parameter_set_identifier: &str) -> PathBuf {
    let dir = Path::new(&parameter_cache_dir_name()).to_path_buf();
    dir.join(format!(
        "v{}-{}.{}",
        VERSION, parameter_set_identifier, VERIFYING_KEY_EXT
    ))
}

fn ensure_ancestor_dirs_exist(cache_entry_path: PathBuf) -> Result<PathBuf> {
    info!(
        "ensuring that all ancestor directories for: {:?} exist",
        cache_entry_path
    );

    if let Some(parent_dir) = cache_entry_path.parent() {
        if let Err(err) = create_dir_all(&parent_dir) {
            match err.kind() {
                io::ErrorKind::AlreadyExists => {}
                _ => return Err(From::from(err)),
            }
        }
    } else {
        return Err(Unclassified(format!(
            "{:?} has no parent directory",
            cache_entry_path
        )));
    }

    Ok(cache_entry_path)
}

pub trait ParameterSetMetadata: Clone {
    fn identifier(&self) -> String;
    fn sector_size(&self) -> u64;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntryMetadata {
    pub sector_size: u64,
}

pub trait CacheableParameters<E, C, P>
where
    C: Circuit<E>,
    E: JubjubEngine,
    P: ParameterSetMetadata,
{
    fn cache_prefix() -> String;

    fn cache_meta(pub_params: &P) -> CacheEntryMetadata {
        CacheEntryMetadata {
            sector_size: pub_params.sector_size(),
        }
    }

    fn cache_identifier(pub_params: &P) -> String {
        let param_identifier = pub_params.identifier();
        info!("parameter set identifier for cache: {}", param_identifier);
        let mut hasher = Sha256::default();
        hasher.input(&param_identifier.into_bytes());
        let circuit_hash = hasher.result();
        format!(
            "{}-{:02x}",
            Self::cache_prefix(),
            circuit_hash.iter().format("")
        )
    }

    fn get_param_metadata(_circuit: C, pub_params: &P) -> Result<CacheEntryMetadata> {
        let id = Self::cache_identifier(pub_params);

        // generate (or load) metadata
        let meta_path = ensure_ancestor_dirs_exist(parameter_cache_metadata_path(&id))?;
        read_cached_metadata(&meta_path)
            .or_else(|_| write_cached_metadata(&meta_path, Self::cache_meta(pub_params)))
    }

    fn get_groth_params(circuit: C, pub_params: &P) -> Result<groth16::Parameters<E>> {
        // Always seed the rng identically so parameter generation will be deterministic.
        let id = Self::cache_identifier(pub_params);

        let generate = || {
            let rng = &mut XorShiftRng::from_seed(PARAMETER_RNG_SEED);
            info!("Actually generating groth params. (id: {})", &id);
            let start = Instant::now();
            let parameters = groth16::generate_random_parameters::<E, _, _>(circuit, rng);
            let generation_time = start.elapsed();
            info!(
                "groth_parameter_generation_time: {:?} (id: {})",
                generation_time, &id
            );
            parameters
        };

        // generate (or load) Groth parameters
        let cache_path = ensure_ancestor_dirs_exist(parameter_cache_params_path(&id))?;
        read_cached_params(&cache_path).or_else(|_| write_cached_params(&cache_path, generate()?))
    }

    fn get_verifying_key(circuit: C, pub_params: &P) -> Result<groth16::VerifyingKey<E>> {
        let id = Self::cache_identifier(pub_params);

        let generate = || -> Result<groth16::VerifyingKey<E>> {
            let groth_params = Self::get_groth_params(circuit, pub_params)?;
            info!("Getting verifying key. (id: {})", &id);
            Ok(groth_params.vk)
        };

        // generate (or load) verifying key
        let cache_path = ensure_ancestor_dirs_exist(parameter_cache_verifying_key_path(&id))?;
        read_cached_verifying_key(&cache_path)
            .or_else(|_| write_cached_verifying_key(&cache_path, generate()?))
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

fn read_cached_params<E: JubjubEngine>(
    cache_entry_path: &PathBuf,
) -> Result<groth16::Parameters<E>> {
    info!("checking cache_path: {:?} for parameters", cache_entry_path);
    with_exclusive_read_lock(cache_entry_path, |mut f| {
        Parameters::read(&mut f, false)
            .map_err(Error::from)
            .map(|value| {
                info!("read parameters from cache {:?} ", cache_entry_path);
                value
            })
    })
}

fn read_cached_verifying_key<E: JubjubEngine>(
    cache_entry_path: &PathBuf,
) -> Result<groth16::VerifyingKey<E>> {
    info!(
        "checking cache_path: {:?} for verifying key",
        cache_entry_path
    );
    with_exclusive_read_lock(cache_entry_path, |mut file| {
        groth16::VerifyingKey::read(&mut file)
            .map_err(Error::from)
            .map(|value| {
                info!("read verifying key from cache {:?} ", cache_entry_path);
                value
            })
    })
}

fn read_cached_metadata(cache_entry_path: &PathBuf) -> Result<CacheEntryMetadata> {
    info!("checking cache_path: {:?} for metadata", cache_entry_path);
    with_exclusive_read_lock(cache_entry_path, |file| {
        serde_json::from_reader(file)
            .map_err(Error::from)
            .map(|value| {
                info!("read metadata from cache {:?} ", cache_entry_path);
                value
            })
    })
}

fn write_cached_metadata(
    cache_entry_path: &PathBuf,
    value: CacheEntryMetadata,
) -> Result<CacheEntryMetadata> {
    with_exclusive_lock(cache_entry_path, |file| {
        serde_json::to_writer(file, &value)
            .map_err(Error::from)
            .map(|_| {
                info!("wrote metadata to cache {:?} ", cache_entry_path);
                value
            })
    })
}

fn write_cached_verifying_key<E: JubjubEngine>(
    cache_entry_path: &PathBuf,
    value: groth16::VerifyingKey<E>,
) -> Result<groth16::VerifyingKey<E>> {
    with_exclusive_lock(cache_entry_path, |file| {
        value.write(file).map_err(Error::from).map(|_| {
            info!("wrote verifying key to cache {:?} ", cache_entry_path);
            value
        })
    })
}

fn write_cached_params<E: JubjubEngine>(
    cache_entry_path: &PathBuf,
    value: groth16::Parameters<E>,
) -> Result<groth16::Parameters<E>> {
    with_exclusive_lock(cache_entry_path, |file| {
        value.write(file).map_err(Error::from).map(|_| {
            info!("wrote groth parameters to cache {:?} ", cache_entry_path);
            value
        })
    })
}

fn with_exclusive_lock<T>(
    file_path: &PathBuf,
    f: impl FnOnce(&mut LockedFile) -> Result<T>,
) -> Result<T> {
    with_open_file(file_path, LockedFile::open_exclusive, f)
}

fn with_exclusive_read_lock<T>(
    file_path: &PathBuf,
    f: impl FnOnce(&mut LockedFile) -> Result<T>,
) -> Result<T> {
    with_open_file(file_path, LockedFile::open_exclusive_read, f)
}

fn with_open_file<'a, T>(
    file_path: &'a PathBuf,
    open_file: impl FnOnce(&'a PathBuf) -> io::Result<LockedFile>,
    f: impl FnOnce(&mut LockedFile) -> Result<T>,
) -> Result<T> {
    ensure_parent(&file_path)?;
    f(&mut open_file(&file_path)?)
}
