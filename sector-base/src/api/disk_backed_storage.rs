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
use proofs_config::ConfigType;

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
        &SBConfiguredStore::ProofTest,
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
        &SBConfiguredStore::Test,
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
        &SBConfiguredStore::Live,
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

    fn num_unsealed_bytes(&self, access: String) -> Result<u64, SectorManagerErr> {
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

    fn truncate_unsealed(&self, access: String, size: u64) -> Result<(), SectorManagerErr> {
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
    fn write_and_preprocess(&self, access: String, data: &[u8]) -> Result<u64, SectorManagerErr> {
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

    fn delete_staging_sector_access(&self, access: String) -> Result<(), SectorManagerErr> {
        remove_file(access).map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
    }

    fn read_raw(
        &self,
        access: String,
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

pub struct ConcreteSectorStore {
    opts: proofs_config::ConfigOpts,
    manager: Box<SectorManager>,
}

impl SectorStore for ConcreteSectorStore {

    fn opts(&self) -> &proofs_config::ConfigOpts {
        &self.opts
    }

    fn manager(&self) -> &SectorManager {
        self.manager.as_ref()
    }
}

pub fn new_sector_store(
    config_type: ConfigType,
    sealed_path: String,
    staging_path: String,
) -> ConcreteSectorStore {
    let manager = Box::new(DiskManager {
        staging_path,
        sealed_path,
    });

    ConcreteSectorStore{ opts: proofs_config::to_opts(config_type), manager }
}

#[cfg(test)]
mod non_ffi_tests {
    use tempfile;

    use super::*;

    fn create_storage() -> ConcreteSectorStore {
        let staging_path = tempfile::tempdir().unwrap().path().to_owned();
        let sealed_path = tempfile::tempdir().unwrap().path().to_owned();

        new_sector_store(
            &SBConfiguredStore::ProofTest,
            String::from(sealed_path.to_str().unwrap()),
            String::from(staging_path.to_str().unwrap()),
        )
    }

    #[test]
    fn deletes_staging_access() {
        let store = create_storage();
        let access = store.manager().new_staging_sector_access().unwrap();

        assert!(store.manager().read_raw(access.clone(), 0, 0).is_ok());
        assert!(store
            .manager()
            .delete_staging_sector_access(access.clone())
            .is_ok());
        assert!(store.manager().read_raw(access.clone(), 0, 0).is_err());
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{create_dir_all, File};
    use std::io::Read;
    use tempfile;

    use super::*;

    use crate::api::disk_backed_storage::init_new_proof_test_sector_store;
    use crate::api::{
        new_staging_sector_access, num_unsealed_bytes, truncate_unsealed, write_and_preprocess,
    };

    use crate::api::responses::SBResponseStatus;
    use crate::io::fr32::FR32_PADDING_MAP;
    use ffi_toolkit::{c_str_to_pbuf, rust_str_to_c_str};

    fn create_storage() -> *mut Box<SectorStore> {
        let staging_path = tempfile::tempdir().unwrap().path().to_owned();
        let sealed_path = tempfile::tempdir().unwrap().path().to_owned();

        create_dir_all(&staging_path).expect("failed to create staging dir");
        create_dir_all(&sealed_path).expect("failed to create sealed dir");

        let s1 = rust_str_to_c_str(staging_path.to_str().unwrap().to_owned());
        let s2 = rust_str_to_c_str(sealed_path.to_str().unwrap().to_owned());

        unsafe { init_new_proof_test_sector_store(s1, s2) }
    }

    fn read_all_bytes(access: *const libc::c_char) -> Vec<u8> {
        let pbuf = unsafe { c_str_to_pbuf(access) };
        let mut file = File::open(pbuf).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    #[test]
    fn unsealed_sector_write_and_truncate() {
        unsafe {
            let storage = create_storage();

            let new_staging_sector_access_response = new_staging_sector_access(storage);

            let access = (*new_staging_sector_access_response).sector_access;

            let contents = &[2u8; 500];

            let write_and_preprocess_response = write_and_preprocess(
                storage,
                (*new_staging_sector_access_response).sector_access,
                &contents[0],
                contents.len(),
            );

            assert_eq!(
                SBResponseStatus::SBNoError,
                (*write_and_preprocess_response).status_code
            );

            // buffer the file's bytes into memory after writing bytes
            let buf = read_all_bytes(access);
            let output_bytes_written = buf.len();

            // ensure that we reported the correct number of written bytes
            assert_eq!(
                contents.len(),
                (*write_and_preprocess_response).num_bytes_written as usize
            );

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(contents[0..32], buf[0..32]);
            assert_eq!(8u8, buf[32]);

            // read the file into memory again - this time after we truncate
            let buf = read_all_bytes(access);

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(504, buf.len());

            // also ensure this is the amount we calculate
            let expected_padded_bytes = FR32_PADDING_MAP.expand_bytes(contents.len());
            assert_eq!(expected_padded_bytes, output_bytes_written);

            {
                let num_unsealed_bytes_response = num_unsealed_bytes(
                    storage,
                    (*new_staging_sector_access_response).sector_access,
                );

                assert_eq!(
                    SBResponseStatus::SBNoError,
                    (*num_unsealed_bytes_response).status_code
                );

                // ensure num_unsealed_bytes returns the number of data bytes written.
                assert_eq!(500, (*num_unsealed_bytes_response).num_bytes as usize);
            }

            {
                // Truncate to 32 unpadded bytes
                assert_eq!(
                    SBResponseStatus::SBNoError,
                    (*truncate_unsealed(storage, access, 32)).status_code
                );

                // read the file into memory again - this time after we truncate
                let buf = read_all_bytes(access);

                // ensure the file we wrote to contains the expected bytes
                assert_eq!(33, buf.len());

                // All but last bytes are identical.
                assert_eq!(contents[0..32], buf[0..32]);

                // The last byte (first of new Fr) has been shifted by two bits of padding.
                assert_eq!(contents[32] << 2, buf[32]);

                let num_unsealed_bytes_response = num_unsealed_bytes(storage, access);

                assert_eq!(
                    SBResponseStatus::SBNoError,
                    (*num_unsealed_bytes_response).status_code
                );

                // ensure that our byte-counting function works
                assert_eq!(32, (*num_unsealed_bytes_response).num_bytes);
            }

            {
                // Truncate to 31 unpadded bytes
                assert_eq!(
                    SBResponseStatus::SBNoError,
                    (*truncate_unsealed(storage, access, 31)).status_code
                );

                // read the file into memory again - this time after we truncate
                let buf = read_all_bytes((*new_staging_sector_access_response).sector_access);

                // ensure the file we wrote to contains the expected bytes
                assert_eq!(31, buf.len());
                assert_eq!(contents[0..31], buf[0..]);

                let num_unsealed_bytes_response = num_unsealed_bytes(storage, access);

                assert_eq!(
                    SBResponseStatus::SBNoError,
                    (*num_unsealed_bytes_response).status_code
                );

                // ensure that our byte-counting function works
                assert_eq!(buf.len(), (*num_unsealed_bytes_response).num_bytes as usize);
            }

            assert_eq!(
                SBResponseStatus::SBNoError,
                (*truncate_unsealed(storage, access, 1)).status_code
            );

            // read the file into memory again - this time after we truncate
            let buf = read_all_bytes(access);

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(1, buf.len());
            assert_eq!(contents[0..1], buf[0..]);

            let num_unsealed_bytes_response = num_unsealed_bytes(storage, access);

            assert_eq!(
                SBResponseStatus::SBNoError,
                (*num_unsealed_bytes_response).status_code
            );

            // ensure that our byte-counting function works
            assert_eq!(buf.len(), (*num_unsealed_bytes_response).num_bytes as usize);
        }
    }
}
