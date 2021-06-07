use std::collections::{BTreeMap, HashSet};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::bail;
use bellperson::{bls::Bls12, groth16, Circuit};
use blake2b_simd::Params as Blake2bParams;
use fs2::FileExt;
use itertools::Itertools;
use lazy_static::lazy_static;
use log::{info, trace};
use memmap::MmapOptions;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{Error, Result},
    settings::SETTINGS,
};

/// Bump this when circuits change to invalidate the cache.
pub const VERSION: usize = 28;
pub const SRS_MAX_PROOFS_TO_AGGREGATE: usize = 65536; // FIXME: placeholder value

pub const GROTH_PARAMETER_EXT: &str = "params";
pub const PARAMETER_METADATA_EXT: &str = "meta";
pub const VERIFYING_KEY_EXT: &str = "vk";
pub const SRS_KEY_EXT: &str = "srs";
pub const SRS_SHARED_KEY_NAME: &str = "fil-inner-product-v1";

#[derive(Debug)]
pub struct LockedFile(File);

pub type ParameterMap = BTreeMap<String, ParameterData>;

#[derive(Debug, Deserialize, Serialize)]
pub struct ParameterData {
    pub cid: String,
    pub digest: String,
    pub sector_size: u64,
}

pub const PARAMETERS_DATA: &str = include_str!("../parameters.json");
pub const SRS_PARAMETERS_DATA: &str = include_str!("../srs-inner-product.json");

lazy_static! {
    pub static ref PARAMETERS: ParameterMap =
        serde_json::from_str(PARAMETERS_DATA).expect("Invalid parameters.json");
    pub static ref SRS_PARAMETERS: ParameterMap =
        serde_json::from_str(SRS_PARAMETERS_DATA).expect("Invalid srs-inner-product.json");
    /// Contains the parameters that were previously verified. This way the parameter files are
    /// only hashed once and not on every usage.
    static ref VERIFIED_PARAMETERS: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

pub fn parameter_id(cache_id: &str) -> String {
    format!("v{}-{}.params", VERSION, cache_id)
}

pub fn verifying_key_id(cache_id: &str) -> String {
    format!("v{}-{}.vk", VERSION, cache_id)
}

pub fn metadata_id(cache_id: &str) -> String {
    format!("v{}-{}.meta", VERSION, cache_id)
}

/// Get the correct parameter data for a given cache id.
pub fn get_parameter_data_from_id(parameter_id: &str) -> Option<&ParameterData> {
    PARAMETERS.get(parameter_id)
}

/// Get the correct srs parameter data for a given cache id.
pub fn get_srs_parameter_data_from_id(parameter_id: &str) -> Option<&ParameterData> {
    SRS_PARAMETERS.get(parameter_id)
}

/// Get the correct parameter data for a given cache id.
pub fn get_parameter_data(cache_id: &str) -> Option<&ParameterData> {
    PARAMETERS.get(&parameter_id(cache_id))
}

/// Get the correct verifying key data for a given cache id.
pub fn get_verifying_key_data(cache_id: &str) -> Option<&ParameterData> {
    PARAMETERS.get(&verifying_key_id(cache_id))
}

// TODO: use in memory lock as well, as file locks do not guarantee exclusive access across OSes.

impl LockedFile {
    pub fn open_exclusive_read<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        let f = OpenOptions::new().read(true).create(false).open(p)?;
        f.lock_exclusive()?;

        Ok(LockedFile(f))
    }

    pub fn open_exclusive<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(p)?;
        f.lock_exclusive()?;

        Ok(LockedFile(f))
    }

    pub fn open_shared_read<P: AsRef<Path>>(p: P) -> io::Result<Self> {
        let f = OpenOptions::new().read(true).create(false).open(p)?;
        f.lock_shared()?;

        Ok(LockedFile(f))
    }
}

impl AsRef<File> for LockedFile {
    fn as_ref(&self) -> &File {
        &self.0
    }
}

impl Write for LockedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Read for LockedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Seek for LockedFile {
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
    SETTINGS.parameter_cache.clone()
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

pub fn parameter_cache_srs_key_path(
    _parameter_set_identifier: &str,
    _num_proofs_to_aggregate: usize,
) -> PathBuf {
    let dir = Path::new(&parameter_cache_dir_name()).to_path_buf();
    dir.join(format!(
        "v{}-{}.{}",
        VERSION, SRS_SHARED_KEY_NAME, SRS_KEY_EXT
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
        bail!("{:?} has no parent directory", cache_entry_path);
    }

    Ok(cache_entry_path)
}

pub trait ParameterSetMetadata {
    fn identifier(&self) -> String;
    fn sector_size(&self) -> u64;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheEntryMetadata {
    pub sector_size: u64,
}

pub trait CacheableParameters<C, P>
where
    C: Circuit<Bls12>,
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
        hasher.update(&param_identifier.into_bytes());
        let circuit_hash = hasher.finalize();
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
            .map_err(Into::into)
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn get_groth_params<R: RngCore>(
        rng: Option<&mut R>,
        circuit: C,
        pub_params: &P,
    ) -> Result<groth16::MappedParameters<Bls12>> {
        let id = Self::cache_identifier(pub_params);
        let cache_path = ensure_ancestor_dirs_exist(parameter_cache_params_path(&id))?;

        let generate = || -> Result<_> {
            if let Some(rng) = rng {
                info!("Actually generating groth params. (id: {})", &id);
                let start = Instant::now();
                let parameters = groth16::generate_random_parameters::<Bls12, _, _>(circuit, rng)?;
                let generation_time = start.elapsed();
                info!(
                    "groth_parameter_generation_time: {:?} (id: {})",
                    generation_time, &id
                );
                Ok(parameters)
            } else {
                bail!(
                    "No cached parameters found for {} [failure finding {}]",
                    id,
                    cache_path.display()
                );
            }
        };

        // load or generate Groth parameter mappings
        read_cached_params(&cache_path).or_else(|err| match err.downcast::<Error>() {
            Ok(error @ Error::InvalidParameters(_)) => Err(error.into()),
            _ => {
                // if the file already exists, another process is already trying to generate these.
                if !cache_path.exists() {
                    match write_cached_params(&cache_path, generate()?) {
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                            // other thread just wrote it, do nothing
                        }
                        Err(e) => panic!("{}: failed to write generated parameters to cache", e),
                    }
                }
                Ok(read_cached_params(&cache_path)?)
            }
        })
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn get_inner_product<R: RngCore>(
        rng: Option<&mut R>,
        _circuit: C,
        pub_params: &P,
        num_proofs_to_aggregate: usize,
    ) -> Result<groth16::aggregate::GenericSRS<Bls12>> {
        let id = Self::cache_identifier(pub_params);
        let cache_path =
            ensure_ancestor_dirs_exist(parameter_cache_srs_key_path(&id, num_proofs_to_aggregate))?;

        let generate = || -> Result<groth16::aggregate::GenericSRS<Bls12>> {
            if let Some(rng) = rng {
                info!(
                    "get_inner_product called with {} [max {}] proofs to aggregate",
                    num_proofs_to_aggregate, SRS_MAX_PROOFS_TO_AGGREGATE
                );
                Ok(groth16::aggregate::setup_fake_srs(
                    rng,
                    num_proofs_to_aggregate,
                ))
            } else {
                bail!(
                    "No cached srs key found for {} [failure finding {}]",
                    id,
                    cache_path.display()
                );
            }
        };

        // generate (or load) srs key
        match read_cached_srs_key(&cache_path) {
            Ok(key) => Ok(key),
            Err(_) => write_cached_srs_key(&cache_path, generate()?).map_err(Into::into),
        }
    }

    /// If the rng option argument is set, parameters will be
    /// generated using it.  This is used for testing only, or where
    /// parameters are otherwise unavailable (e.g. benches).  If rng
    /// is not set, an error will result if parameters are not
    /// present.
    fn get_verifying_key<R: RngCore>(
        rng: Option<&mut R>,
        circuit: C,
        pub_params: &P,
    ) -> Result<groth16::VerifyingKey<Bls12>> {
        let id = Self::cache_identifier(pub_params);

        let generate = || -> Result<groth16::VerifyingKey<Bls12>> {
            let groth_params = Self::get_groth_params(rng, circuit, pub_params)?;
            info!("Getting verifying key. (id: {})", &id);
            Ok(groth_params.vk)
        };

        // generate (or load) verifying key
        let cache_path = ensure_ancestor_dirs_exist(parameter_cache_verifying_key_path(&id))?;
        match read_cached_verifying_key(&cache_path) {
            Ok(key) => Ok(key),
            Err(_) => write_cached_verifying_key(&cache_path, generate()?).map_err(Into::into),
        }
    }
}

fn ensure_parent(path: &Path) -> io::Result<()> {
    match path.parent() {
        Some(dir) => {
            create_dir_all(dir)?;
            Ok(())
        }
        None => Ok(()),
    }
}

// Reads parameter mappings using mmap so that they can be lazily
// loaded later.
pub fn read_cached_params(cache_entry_path: &Path) -> Result<groth16::MappedParameters<Bls12>> {
    info!("checking cache_path: {:?} for parameters", cache_entry_path);

    let verify_production_params = SETTINGS.verify_production_params;

    // If the verify production params is set, we make sure that the path being accessed matches a
    // production cache key, found in the 'srs-inner-product.json' file. The parameter data file is
    // also hashed and matched against the hash in the 'srs-inner-product.json' file.
    if verify_production_params {
        let cache_key = cache_entry_path
            .file_name()
            .expect("failed to get cached srs filename")
            .to_str()
            .expect("failed to convert to str")
            .to_string();

        match get_parameter_data_from_id(&cache_key) {
            Some(data) => {
                // Verify the actual hash only once per parameters file
                let not_yet_verified = VERIFIED_PARAMETERS
                    .lock()
                    .expect("verified parameters lock failed")
                    .get(&cache_key)
                    .is_none();
                if not_yet_verified {
                    info!("generating consistency digest for parameters");
                    let hash = with_exclusive_read_lock::<_, io::Error, _>(
                        cache_entry_path,
                        |mut file| {
                            let mut hasher = Blake2bParams::new().to_state();
                            io::copy(&mut file, &mut hasher)
                                .expect("copying file into hasher failed");
                            Ok(hasher.finalize())
                        },
                    )?;
                    info!("generated consistency digest for parameters");

                    // The hash in the parameters file is truncated to 256 bits.
                    let digest_hex = &hash.to_hex()[..32];

                    if digest_hex != data.digest {
                        return Err(Error::InvalidParameters(
                            cache_entry_path.display().to_string(),
                        )
                        .into());
                    }

                    trace!("parameter data is valid [{}]", digest_hex);
                    VERIFIED_PARAMETERS
                        .lock()
                        .expect("verified parameters lock failed")
                        .insert(cache_key);
                }
            }
            None => {
                return Err(Error::InvalidParameters(cache_entry_path.display().to_string()).into())
            }
        }
    }

    with_exclusive_read_lock::<_, io::Error, _>(cache_entry_path, |_file| {
        let mapped_params =
            groth16::Parameters::build_mapped_parameters(cache_entry_path.to_path_buf(), false)?;
        info!("read parameters from cache {:?} ", cache_entry_path);

        Ok(mapped_params)
    })
    .map_err(Into::into)
}

fn read_cached_verifying_key(cache_entry_path: &Path) -> io::Result<groth16::VerifyingKey<Bls12>> {
    info!(
        "checking cache_path: {:?} for verifying key",
        cache_entry_path
    );
    with_exclusive_read_lock(cache_entry_path, |mut file| {
        let key = groth16::VerifyingKey::read(&mut file)?;
        info!("read verifying key from cache {:?} ", cache_entry_path);

        Ok(key)
    })
}

fn read_cached_srs_key(cache_entry_path: &Path) -> Result<groth16::aggregate::GenericSRS<Bls12>> {
    info!("checking cache_path: {:?} for srs", cache_entry_path);

    let verify_production_params = SETTINGS.verify_production_params;

    // If the verify production params is set, we make sure that the path being accessed matches a
    // production cache key, found in the 'parameters.json' file. The parameter data file is also
    // hashed and matched against the hash in the `parameters.json` file.
    if verify_production_params {
        let cache_key = cache_entry_path
            .file_name()
            .expect("failed to get cached srs filename")
            .to_str()
            .expect("failed to convert to str")
            .to_string();

        match get_srs_parameter_data_from_id(&cache_key) {
            Some(data) => {
                // Verify the actual hash only once per parameters file
                let not_yet_verified = VERIFIED_PARAMETERS
                    .lock()
                    .expect("verified parameters lock failed")
                    .get(&cache_key)
                    .is_none();
                if not_yet_verified {
                    info!("generating consistency digest for srs");
                    let hash = with_exclusive_read_lock::<_, io::Error, _>(
                        cache_entry_path,
                        |mut file| {
                            let mut hasher = Blake2bParams::new().to_state();
                            io::copy(&mut file, &mut hasher)
                                .expect("copying file into hasher failed");
                            Ok(hasher.finalize())
                        },
                    )?;
                    info!("generated consistency digest for srs");

                    // The hash in the parameters file is truncated to 256 bits.
                    let digest_hex = &hash.to_hex()[..32];

                    if digest_hex != data.digest {
                        return Err(Error::InvalidParameters(
                            cache_entry_path.display().to_string(),
                        )
                        .into());
                    }

                    trace!("srs data is valid [{}]", digest_hex);
                    VERIFIED_PARAMETERS
                        .lock()
                        .expect("verified parameters lock failed")
                        .insert(cache_key);
                }
            }
            None => {
                return Err(Error::InvalidParameters(cache_entry_path.display().to_string()).into())
            }
        }
    }

    with_exclusive_read_lock(cache_entry_path, |file| {
        let srs_map = unsafe { MmapOptions::new().map(file.as_ref())? };
        // NOTE: We do not currently support lengths higher than this,
        // even though the SRS file can handle up to (2 << 19) + 1
        // elements.  Specifying under that limit speeds up
        // performance quite a bit.
        let max_len = (2 << 14) + 1;
        let key = groth16::aggregate::GenericSRS::read_mmap(&srs_map, max_len)?;
        info!("read srs key from cache {:?} ", cache_entry_path);

        Ok(key)
    })
}

fn read_cached_metadata(cache_entry_path: &Path) -> io::Result<CacheEntryMetadata> {
    info!("checking cache_path: {:?} for metadata", cache_entry_path);
    with_exclusive_read_lock(cache_entry_path, |file| {
        let value = serde_json::from_reader(file)?;
        info!("read metadata from cache {:?} ", cache_entry_path);

        Ok(value)
    })
}

fn write_cached_metadata(
    cache_entry_path: &Path,
    value: CacheEntryMetadata,
) -> io::Result<CacheEntryMetadata> {
    with_exclusive_lock(cache_entry_path, |file| {
        serde_json::to_writer(file, &value)?;
        info!("wrote metadata to cache {:?} ", cache_entry_path);

        Ok(value)
    })
}

fn write_cached_verifying_key(
    cache_entry_path: &Path,
    value: groth16::VerifyingKey<Bls12>,
) -> io::Result<groth16::VerifyingKey<Bls12>> {
    with_exclusive_lock(cache_entry_path, |mut file| {
        value.write(&mut file)?;
        file.flush()?;
        info!("wrote verifying key to cache {:?} ", cache_entry_path);

        Ok(value)
    })
}

fn write_cached_srs_key(
    cache_entry_path: &Path,
    value: groth16::aggregate::GenericSRS<Bls12>,
) -> io::Result<groth16::aggregate::GenericSRS<Bls12>> {
    with_exclusive_lock(cache_entry_path, |mut file| {
        value.write(&mut file)?;
        file.flush()?;
        info!("wrote srs key to cache {:?} ", cache_entry_path);

        Ok(value)
    })
}

fn write_cached_params(
    cache_entry_path: &Path,
    value: groth16::Parameters<Bls12>,
) -> io::Result<groth16::Parameters<Bls12>> {
    with_exclusive_lock(cache_entry_path, |mut file| {
        value.write(&mut file)?;
        file.flush()?;
        info!("wrote groth parameters to cache {:?} ", cache_entry_path);

        Ok(value)
    })
}

pub fn with_exclusive_lock<T, E, F>(file_path: &Path, f: F) -> std::result::Result<T, E>
where
    F: FnOnce(&mut LockedFile) -> std::result::Result<T, E>,
    E: From<io::Error>,
{
    with_open_file(file_path, LockedFile::open_exclusive, f)
}

pub fn with_exclusive_read_lock<T, E, F>(file_path: &Path, f: F) -> std::result::Result<T, E>
where
    F: FnOnce(&mut LockedFile) -> std::result::Result<T, E>,
    E: From<io::Error>,
{
    with_open_file(file_path, LockedFile::open_exclusive_read, f)
}

pub fn with_open_file<'a, T, E, F, G>(
    file_path: &'a Path,
    open_file: G,
    f: F,
) -> std::result::Result<T, E>
where
    F: FnOnce(&mut LockedFile) -> std::result::Result<T, E>,
    G: FnOnce(&'a Path) -> io::Result<LockedFile>,
    E: From<io::Error>,
{
    ensure_parent(&file_path)?;
    f(&mut open_file(file_path)?)
}
