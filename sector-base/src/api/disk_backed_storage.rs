use libc;
use std::fs::{create_dir_all, remove_file, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::api::bytes_amount::{PaddedBytesAmount, UnpaddedBytesAmount};
use crate::api::errors::SectorManagerErr;
use crate::api::sector_store::SectorConfig;
use crate::api::sector_store::SectorManager;
use crate::api::sector_store::SectorStore;
use crate::api::util;
use crate::io::fr32::almost_truncate_to_unpadded_bytes;
use crate::io::fr32::target_unpadded_bytes;
use crate::io::fr32::unpadded_bytes;
use crate::io::fr32::write_padded;
use ffi_toolkit::{c_str_to_rust_str, raw_ptr};

// These sizes are for SEALED sectors. They are used to calculate the values of setup parameters.
// They can be overridden by setting the corresponding environment variable (with FILECOIN_PROOFS_ prefix),
// but this is not recommended, since some sealed sector sizes are invalid. If you must set this manually,
// ensure the chosen sector size is a multiple of 32.

// Sector size, in bytes, for tests.
pub const TEST_SECTOR_SIZE: u64 = 1024;

// Sector size, in bytes, during live operation.
pub const LIVE_SECTOR_SIZE: u64 = 1 << 28; // 256MiB

/// Initializes and returns a boxed SectorStore instance with very small, unrealistic/insecure parameters
/// for use in testing.
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

/// Initializes and returns a boxed SectorStore instance for non-test use.
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
    fn write_and_preprocess(
        &self,
        access: &str,
        data: &[u8],
    ) -> Result<UnpaddedBytesAmount, SectorManagerErr> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(access)
            .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
            .and_then(|mut file| {
                write_padded(data, &mut file)
                    .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
                    .map(|n| UnpaddedBytesAmount(n as u64))
            })
    }

    fn delete_staging_sector_access(&self, access: &str) -> Result<(), SectorManagerErr> {
        remove_file(access).map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
    }

    fn read_raw(
        &self,
        access: &str,
        start_offset: u64,
        num_bytes: UnpaddedBytesAmount,
    ) -> Result<Vec<u8>, SectorManagerErr> {
        OpenOptions::new()
            .read(true)
            .open(access)
            .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
            .and_then(|mut file| -> Result<Vec<u8>, SectorManagerErr> {
                file.seek(SeekFrom::Start(start_offset))
                    .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))?;

                let mut buf = vec![0; usize::from(num_bytes)];

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

pub struct Config {
    pub sector_bytes: u64,
}

#[derive(Debug)]
#[repr(C)]
pub enum ConfiguredStore {
    Live = 0,
    Test = 1,
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
        ConfiguredStore::Live => Box::new(Config {
            sector_bytes: LIVE_SECTOR_SIZE,
        }),
        ConfiguredStore::Test => Box::new(Config {
            sector_bytes: TEST_SECTOR_SIZE,
        }),
    }
}

impl SectorConfig for Config {
    fn max_unsealed_bytes_per_sector(&self) -> UnpaddedBytesAmount {
        UnpaddedBytesAmount(unpadded_bytes(self.sector_bytes))
    }

    fn sector_bytes(&self) -> PaddedBytesAmount {
        PaddedBytesAmount(self.sector_bytes)
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
            (ConfiguredStore::Live, 266338304),
            (ConfiguredStore::Test, 1016),
        ];

        for (configured_store, num_bytes) in xs {
            let storage: Box<SectorStore> = create_sector_store(&configured_store);
            let cfg = storage.config();
            assert_eq!(u64::from(cfg.max_unsealed_bytes_per_sector()), num_bytes);
        }
    }

    #[test]
    fn unsealed_sector_write_and_truncate() {
        let configured_store = ConfiguredStore::Test;
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
            assert_eq!(contents.len(), usize::from(n));

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(contents[0..32], buf[0..32]);
            assert_eq!(8u8, buf[32]);

            // read the file into memory again - this time after we truncate
            let buf = read_all_bytes(&access);

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(504, buf.len());

            // also ensure this is the amount we calculate
            let expected_padded_bytes =
                FR32_PADDING_MAP.transform_byte_offset(contents.len(), true);
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
        let configured_store = ConfiguredStore::Test;

        let store = create_sector_store(&configured_store);
        let access = store.manager().new_staging_sector_access().unwrap();

        assert!(store
            .manager()
            .read_raw(&access, 0, UnpaddedBytesAmount(0))
            .is_ok());

        assert!(store
            .manager()
            .delete_staging_sector_access(&access)
            .is_ok());

        assert!(store
            .manager()
            .read_raw(&access, 0, UnpaddedBytesAmount(0))
            .is_err());
    }
}
