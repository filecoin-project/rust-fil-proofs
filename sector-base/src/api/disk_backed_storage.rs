use crate::api::errors::SectorManagerErr;
use crate::api::sector_store::{SectorConfig, SectorManager, SectorStore};
use crate::api::util;
use crate::io::fr32::{
    almost_truncate_to_unpadded_bytes, target_unpadded_bytes, unpadded_bytes, write_padded,
};
use ffi_toolkit::{c_str_to_rust_str, raw_ptr};
use libc;
use std::env;
use std::fs::{create_dir_all, remove_file, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

// These sizes are for SEALED sectors. They are used to calculate the values of setup parameters.
// They can be overridden by setting the corresponding environment variable (with FILECOIN_PROOFS_ prefix),
// but this is not recommended, since some sealed sector sizes are invalid. If you must set this manually,
// ensure the chosen sector size is a multiple of 32.

// Sector size, in bytes, to use when testing real proofs. (real sector store)
pub const REAL_SECTOR_SIZE: u64 = 128; // Override with FILECOIN_PROOFS_REAL_SECTOR_SIZE env var.

// Sector size, in bytes, for tests which fake sealing with a subset of the data. (fast fake sector store)
pub const FAST_SECTOR_SIZE: u64 = 1024; // Override with FILECOIN_PROOFS_FAST_SECTOR_SIZE env var.

// Sector size, in bytes, during live operation -- which also fakes sealing with a subset of the data. (slow fake sector store)
pub const SLOW_SECTOR_SIZE: u64 = 1 << 30; // Override with FILECOIN_PROOFS_SLOW_SECTOR_SIZE env var.

// The delay constants can be overridden by setting the corresponding environment variable (with FILECOIN_PROOFS_ prefix)
// For example, since SLOW_DELAY_SECONDS is used for live sealing, outside of tests,
// setting the environment variable, FILECOIN_PROOFS_SLOW_DELAY_SECONDS to 30, will result in sealing
// which takes approximately 30 seconds (with 15 seconds to get unsealed data).

// Delay, in seconds, for tests which fake sealing with a subset of the data. (fast fake sector store)
pub const FAST_DELAY_SECONDS: u32 = 10; // Override with FILECOIN_PROOFS_FAST_DELAY_SECONDS env var.

// Delay, in seconds during live operation which also fakes sealing with a subset of the data. (slow fake sector store)
pub const SLOW_DELAY_SECONDS: u32 = 0; // Override with FILECOIN_PROOFS_SLOW_DELAY_SECONDS env var.

fn sector_size(env_var_name: &str, default: u64) -> u64 {
    match env::var(env_var_name) {
        Ok(bytes_string) => bytes_string.parse().unwrap_or(default),
        Err(_) => default,
    }
}

fn delay_seconds(env_var_name: &str, default: u32) -> u32 {
    match env::var(env_var_name) {
        Ok(seconds_string) => seconds_string.parse().unwrap_or(default),
        Err(_) => default,
    }
}

/// Initializes and returns a boxed SectorStore instance suitable for exercising the proofs code
/// to its fullest capacity.
///
/// # Arguments
///
/// * `staging_dir_path` - path to the staging directory
/// * `sealed_dir_path`  - path to the sealed directory
#[no_mangle]
pub unsafe extern "C" fn init_new_proof_test_sector_store(
    staging_dir_path: *const libc::c_char,
    sealed_dir_path: *const libc::c_char,
) -> *mut Box<SectorStore> {
    let boxed = Box::new(new_sector_store(
        &ConfiguredStore::ProofTest,
        c_str_to_rust_str(sealed_dir_path).to_string(),
        c_str_to_rust_str(staging_dir_path).to_string(),
    ));
    raw_ptr(boxed)
}

/// Initializes and returns a boxed SectorStore instance which is very similar to the Alpha-release
/// SectorStore that Filecoin node-users will rely upon - but with manageably-small delays for seal
/// and unseal.
///
/// # Arguments
///
/// * `staging_dir_path` - path to the staging directory
/// * `sealed_dir_path`  - path to the sealed directory
#[no_mangle]
pub unsafe extern "C" fn init_new_test_sector_store(
    staging_dir_path: *const libc::c_char,
    sealed_dir_path: *const libc::c_char,
) -> *mut Box<SectorStore> {
    let boxed = Box::new(new_sector_store(
        &ConfiguredStore::Test,
        c_str_to_rust_str(sealed_dir_path).to_string(),
        c_str_to_rust_str(staging_dir_path).to_string(),
    ));
    raw_ptr(boxed)
}

/// Initializes and returns a boxed SectorStore instance which Alpha Filecoin node-users will rely
/// upon. Some operations are substantially delayed; sealing an unsealed sector using this could
/// take several hours.
///
/// # Arguments
///
/// * `staging_dir_path` - path to the staging directory
/// * `sealed_dir_path`  - path to the sealed directory
#[no_mangle]
pub unsafe extern "C" fn init_new_sector_store(
    staging_dir_path: *const libc::c_char,
    sealed_dir_path: *const libc::c_char,
) -> *mut Box<SectorStore> {
    let boxed = Box::new(new_sector_store(
        &ConfiguredStore::Live,
        c_str_to_rust_str(sealed_dir_path).to_string(),
        c_str_to_rust_str(staging_dir_path).to_string(),
    ));

    raw_ptr(boxed)
}

/// Destroys a boxed SectorStore by freeing its memory.
///
/// # Arguments
///
/// * `ss_ptr` - pointer to a boxed SectorStore
///
#[no_mangle]
pub unsafe extern "C" fn destroy_storage(ss_ptr: *mut Box<SectorStore>) {
    let _ = Box::from_raw(ss_ptr);
}

pub struct DiskManager {
    staging_path: String,
    sealed_path: String,
}

impl SectorManager for DiskManager {
    fn new_sealed_sector_access(&self) -> Result<String, SectorManagerErr> {
        self.new_sector_access(Path::new(&self.sealed_path))
    }

    fn new_staging_sector_access(&self) -> Result<String, SectorManagerErr> {
        self.new_sector_access(Path::new(&self.staging_path))
    }

    fn num_unsealed_bytes(&self, access: &str) -> Result<u64, SectorManagerErr> {
        OpenOptions::new()
            .read(true)
            .open(access)
            .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
            .map(|mut f| {
                target_unpadded_bytes(&mut f)
                    .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
            })
            .and_then(|n| n)
    }

    fn truncate_unsealed(&self, access: &str, size: u64) -> Result<(), SectorManagerErr> {
        // I couldn't wrap my head around all ths result mapping, so here it is all laid out.
        match OpenOptions::new().write(true).open(&access) {
            Ok(mut file) => match almost_truncate_to_unpadded_bytes(&mut file, size) {
                Ok(padded_size) => match file.set_len(padded_size as u64) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SectorManagerErr::ReceiverError(format!("{:?}", err))),
                },
                Err(err) => Err(SectorManagerErr::ReceiverError(format!("{:?}", err))),
            },
            Err(err) => Err(SectorManagerErr::CallerError(format!("{:?}", err))),
        }
    }

    // TODO: write_and_preprocess should refuse to write more data than will fit. In that case, return 0.
    fn write_and_preprocess(&self, access: &str, data: &[u8]) -> Result<u64, SectorManagerErr> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(access)
            .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
            .and_then(|mut file| {
                write_padded(data, &mut file)
                    .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
                    .map(|n| n as u64)
            })
    }

    fn delete_staging_sector_access(&self, access: &str) -> Result<(), SectorManagerErr> {
        remove_file(access).map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
    }

    fn read_raw(
        &self,
        access: &str,
        start_offset: u64,
        num_bytes: u64,
    ) -> Result<Vec<u8>, SectorManagerErr> {
        OpenOptions::new()
            .read(true)
            .open(access)
            .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
            .and_then(|mut file| -> Result<Vec<u8>, SectorManagerErr> {
                file.seek(SeekFrom::Start(start_offset))
                    .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))?;

                let mut buf = vec![0; num_bytes as usize];

                file.read_exact(buf.as_mut_slice())
                    .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))?;

                Ok(buf)
            })
    }
}

impl DiskManager {
    fn new_sector_access(&self, root: &Path) -> Result<String, SectorManagerErr> {
        let pbuf = root.join(util::rand_alpha_string(32));

        create_dir_all(root)
            .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
            .and_then(|_| {
                File::create(&pbuf)
                    .map(|_| 0)
                    .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
            })
            .and_then(|_| {
                pbuf.to_str().map_or_else(
                    || {
                        Err(SectorManagerErr::ReceiverError(
                            "could not create pbuf".to_string(),
                        ))
                    },
                    |str_ref| Ok(str_ref.to_owned()),
                )
            })
    }
}

pub struct RealConfig {
    sector_bytes: u64,
}

pub struct FakeConfig {
    sector_bytes: u64,
    delay_seconds: u32,
}

#[derive(Debug)]
#[repr(C)]
pub enum ConfiguredStore {
    Live = 0,
    Test = 1,
    ProofTest = 2,
}

pub struct ConcreteSectorStore {
    config: Box<SectorConfig>,
    manager: Box<SectorManager>,
}

impl SectorStore for ConcreteSectorStore {
    fn config(&self) -> &SectorConfig {
        self.config.as_ref()
    }

    fn manager(&self) -> &SectorManager {
        self.manager.as_ref()
    }
}

pub fn new_sector_store(
    cs: &ConfiguredStore,
    sealed_path: String,
    staging_path: String,
) -> ConcreteSectorStore {
    let manager = Box::new(DiskManager {
        staging_path,
        sealed_path,
    });

    let config = new_sector_config(cs);

    ConcreteSectorStore { config, manager }
}

pub fn new_sector_config(cs: &ConfiguredStore) -> Box<SectorConfig> {
    match *cs {
        ConfiguredStore::Live => Box::new(FakeConfig {
            sector_bytes: sector_size("FILECOIN_PROOFS_SLOW_SECTOR_SIZE", SLOW_SECTOR_SIZE),
            delay_seconds: delay_seconds("FILECOIN_PROOFS_SLOW_DELAY_SECONDS", SLOW_DELAY_SECONDS),
        }),
        ConfiguredStore::Test => Box::new(FakeConfig {
            sector_bytes: sector_size("FILECOIN_PROOFS_FAST_SECTOR_SIZE", FAST_SECTOR_SIZE),
            delay_seconds: delay_seconds("FILECOIN_PROOFS_FAST_DELAY_SECONDS", FAST_DELAY_SECONDS),
        }),
        ConfiguredStore::ProofTest => Box::new(RealConfig {
            sector_bytes: sector_size("FILECOIN_PROOFS_SECTOR_SIZE", REAL_SECTOR_SIZE),
        }),
    }
}

impl SectorConfig for RealConfig {
    fn is_fake(&self) -> bool {
        false
    }

    fn simulate_delay_seconds(&self) -> Option<u32> {
        None
    }

    fn max_unsealed_bytes_per_sector(&self) -> u64 {
        unpadded_bytes(self.sector_bytes)
    }

    fn sector_bytes(&self) -> u64 {
        self.sector_bytes
    }

    fn dummy_parameter_cache_name(&self) -> String {
        String::from("REAL_DUMMY_API_PARAMETERS")
    }
}

impl SectorConfig for FakeConfig {
    fn is_fake(&self) -> bool {
        true
    }

    fn simulate_delay_seconds(&self) -> Option<u32> {
        Some(self.delay_seconds)
    }

    fn max_unsealed_bytes_per_sector(&self) -> u64 {
        unpadded_bytes(self.sector_bytes)
    }

    fn sector_bytes(&self) -> u64 {
        self.sector_bytes
    }

    fn dummy_parameter_cache_name(&self) -> String {
        String::from("FAKE_DUMMY_API_PARAMETERS_{}")
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::io::fr32::FR32_PADDING_MAP;
    use std::fs::create_dir_all;
    use std::fs::File;
    use std::io::Read;
    use tempfile;

    fn create_sector_store(cs: &ConfiguredStore) -> Box<SectorStore> {
        let staging_path = tempfile::tempdir().unwrap().path().to_owned();
        let sealed_path = tempfile::tempdir().unwrap().path().to_owned();

        create_dir_all(&staging_path).expect("failed to create staging dir");
        create_dir_all(&sealed_path).expect("failed to create sealed dir");

        Box::new(new_sector_store(
            &cs,
            sealed_path.to_str().unwrap().to_owned(),
            staging_path.to_str().unwrap().to_owned(),
        ))
    }

    fn read_all_bytes(access: &str) -> Vec<u8> {
        let mut file = File::open(access).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    #[test]
    fn max_unsealed_bytes_per_sector_checks() {
        let xs = vec![
            (ConfiguredStore::Live, 1065353216),
            (ConfiguredStore::Test, 1016),
            (ConfiguredStore::ProofTest, 127),
        ];

        for (configured_store, num_bytes) in xs {
            let storage: Box<SectorStore> = create_sector_store(&configured_store);
            let cfg = storage.config();
            assert_eq!(cfg.max_unsealed_bytes_per_sector(), num_bytes);
        }
    }

    #[test]
    fn unsealed_sector_write_and_truncate() {
        let configured_store = ConfiguredStore::ProofTest;
        let storage: Box<SectorStore> = create_sector_store(&configured_store);
        let mgr = storage.manager();

        let access = mgr
            .new_staging_sector_access()
            .expect("failed to create staging file");

        // shared amongst test cases
        let contents = &[2u8; 500];

        // write_and_preprocess
        {
            let n = mgr
                .write_and_preprocess(&access, contents)
                .expect("failed to write");

            // buffer the file's bytes into memory after writing bytes
            let buf = read_all_bytes(&access);
            let output_bytes_written = buf.len();

            // ensure that we reported the correct number of written bytes
            assert_eq!(contents.len(), n as usize);

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(contents[0..32], buf[0..32]);
            assert_eq!(8u8, buf[32]);

            // read the file into memory again - this time after we truncate
            let buf = read_all_bytes(&access);

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(504, buf.len());

            // also ensure this is the amount we calculate
            let expected_padded_bytes = FR32_PADDING_MAP.expand_bytes(contents.len());
            assert_eq!(expected_padded_bytes, output_bytes_written);

            // ensure num_unsealed_bytes returns the number of data bytes written.
            let num_bytes_written = mgr
                .num_unsealed_bytes(&access)
                .expect("failed to get num bytes");
            assert_eq!(500, num_bytes_written as usize);
        }

        // truncation and padding
        {
            let xs: Vec<(usize, bool)> = vec![(32, true), (31, false), (1, false)];

            for (num_bytes, expect_fr_shift) in xs {
                mgr.truncate_unsealed(&access, num_bytes as u64)
                    .expect("failed to truncate");

                // read the file into memory again - this time after we truncate
                let buf = read_all_bytes(&access);

                // All but last bytes are identical.
                assert_eq!(contents[0..num_bytes], buf[0..num_bytes]);

                if expect_fr_shift {
                    // The last byte (first of new Fr) has been shifted by two bits of padding.
                    assert_eq!(contents[num_bytes] << 2, buf[num_bytes]);

                    // ensure the buffer contains the extra byte
                    assert_eq!(num_bytes + 1, buf.len());
                } else {
                    // no extra byte here
                    assert_eq!(num_bytes, buf.len());
                }

                // ensure num_unsealed_bytes returns the correct number post-truncation
                let num_bytes_written = mgr
                    .num_unsealed_bytes(&access)
                    .expect("failed to get num bytes");
                assert_eq!(num_bytes, num_bytes_written as usize);
            }
        }
    }

    #[test]
    fn deletes_staging_access() {
        let configured_store = ConfiguredStore::ProofTest;

        let store = create_sector_store(&configured_store);
        let access = store.manager().new_staging_sector_access().unwrap();

        assert!(store.manager().read_raw(&access, 0, 0).is_ok());

        assert!(store
            .manager()
            .delete_staging_sector_access(&access)
            .is_ok());

        assert!(store.manager().read_raw(&access, 0, 0).is_err());
    }
}
