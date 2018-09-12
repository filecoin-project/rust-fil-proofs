use std::ffi::CString;
use std::fs::{create_dir_all, metadata, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::forget;
use std::path::Path;
use std::slice;

use libc;

use api::SectorStore;

use super::{rand_alpha_string, str_from_c};
use api::StatusCode;

pub struct DiskBackedStorage {
    staging_path: String,
    sealed_path: String,
}

impl DiskBackedStorage {
    unsafe fn new_sector_access(
        &self,
        root: &Path,
        result: *mut *const libc::c_char,
    ) -> StatusCode {
        let pbuf = root.join(rand_alpha_string(32));

        let create_result = match create_dir_all(root) {
            Err(_) => 70,
            Ok(_) => match File::create(&pbuf) {
                Err(_) => 71,
                Ok(_) => 0,
            },
        };

        if create_result != 0 {
            return create_result;
        }

        match pbuf.to_str() {
            None => 72,
            Some(str_ref) => match CString::new(str_ref) {
                Err(_) => 73,
                Ok(c_string) => {
                    let ptr = c_string.as_ptr();
                    forget(c_string);
                    result.write(ptr);

                    0
                }
            },
        }
    }
}

/// Initializes and returns a boxed DiskBackedStorage, used to dispense sector access.
///
/// # Arguments
///
/// * `staging_dir_path` - path to the staging directory
/// * `sealed_dir_path`  - path to the sealed directory
/// ```
#[no_mangle]
pub unsafe extern "C" fn init_disk_backed_storage(
    staging_dir_path: *const libc::c_char,
    sealed_dir_path: *const libc::c_char,
) -> *mut Box<SectorStore> {
    let m = DiskBackedStorage {
        sealed_path: String::from(str_from_c(sealed_dir_path)),
        staging_path: String::from(str_from_c(staging_dir_path)),
    };

    Box::into_raw(Box::new(Box::new(m)))
}

impl SectorStore for DiskBackedStorage {
    unsafe fn is_fake(&self) -> bool {
        false
    }

    unsafe fn simulate_delay(&self) -> bool {
        true
    }

    unsafe fn num_bytes_per_sector(&self) -> u64 {
        64
    }

    unsafe fn new_sealed_sector_access(&self, result_ptr: *mut *const libc::c_char) -> StatusCode {
        self.new_sector_access(Path::new(&self.sealed_path), result_ptr)
    }

    unsafe fn new_staging_sector_access(&self, result_ptr: *mut *const libc::c_char) -> StatusCode {
        self.new_sector_access(Path::new(&self.staging_path), result_ptr)
    }

    unsafe fn num_unsealed_bytes(
        &self,
        access: *const libc::c_char,
        result_ptr: *mut u64,
    ) -> StatusCode {
        let path = String::from(str_from_c(access));

        match metadata(path) {
            Ok(m) => {
                result_ptr.write(m.len());

                0
            }
            Err(_) => 60,
        }
    }

    unsafe fn truncate_unsealed(&self, access: *const libc::c_char, size: u64) -> StatusCode {
        let path = String::from(str_from_c(access));

        let access_open_opts = OpenOptions::new().write(true).open(path);

        match access_open_opts {
            Ok(access_file) => match access_file.set_len(size) {
                Ok(_) => 0,
                Err(_) => 51,
            },
            Err(_) => 50,
        }
    }

    unsafe fn write_unsealed(
        &self,
        access: *const libc::c_char,
        data_ptr: *const u8,
        data_len: usize,
        result_ptr: *mut u64,
    ) -> StatusCode {
        let data = slice::from_raw_parts(data_ptr as *const u8, data_len as usize);

        let path = String::from(str_from_c(access));

        let access_open_opts = OpenOptions::new().read(true).append(true).open(path);

        match access_open_opts {
            Ok(access_file) => {
                let mut buf_writer = BufWriter::new(access_file);

                match buf_writer.write(&data) {
                    Ok(num_bytes_written) => {
                        result_ptr.write(num_bytes_written as u64);

                        0
                    }
                    Err(_) => 41,
                }
            }
            Err(_) => 40,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::{create_dir_all, File};
    use std::io::Read;
    use tempfile;

    use super::super::pbuf_from_c;
    use super::*;

    use api::disk_backed_storage::init_disk_backed_storage;
    use api::{
        new_staging_sector_access, num_unsealed_bytes, truncate_unsealed, write_unsealed,
        SectorAccess,
    };

    fn rust_str_to_c_str(s: &str) -> *const libc::c_char {
        CString::new(s).unwrap().into_raw()
    }

    fn create_storage() -> *mut Box<SectorStore> {
        let staging_path = tempfile::tempdir().unwrap().path().to_owned();
        let sealed_path = tempfile::tempdir().unwrap().path().to_owned();

        create_dir_all(&staging_path).expect("failed to create staging dir");
        create_dir_all(&sealed_path).expect("failed to create sealed dir");

        let s1 = rust_str_to_c_str(&staging_path.to_str().unwrap().to_owned());
        let s2 = rust_str_to_c_str(&sealed_path.to_str().unwrap().to_owned());

        unsafe { init_disk_backed_storage(s1, s2) }
    }

    fn read_all_bytes(access: SectorAccess) -> Vec<u8> {
        let pbuf = unsafe { pbuf_from_c(access) };
        let mut file = File::open(pbuf).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    #[test]
    fn unsealed_sector_write_and_truncate() {
        let storage = create_storage();

        let access = unsafe {
            let result = &mut rust_str_to_c_str("");
            new_staging_sector_access(storage, result);
            *result
        };

        let contents = b"hello, moto";
        let write_result_ptr = &mut 0u64;

        assert_eq!(0, unsafe {
            write_unsealed(
                storage,
                access,
                &contents[0],
                contents.len(),
                write_result_ptr,
            )
        });

        // buffer the file's bytes into memory after writing bytes
        let buf = read_all_bytes(access);

        // ensure that we reported the correct number of written bytes
        assert_eq!(contents.len(), *write_result_ptr as usize);

        // ensure the file we wrote to contains the expected bytes
        assert_eq!(contents.len(), buf.len());
        assert_eq!(contents[0..], buf[0..]);

        assert_eq!(0, unsafe { truncate_unsealed(storage, access, 1) });

        // read the file into memory again - this time after we truncate
        let buf = read_all_bytes(access);

        // ensure the file we wrote to contains the expected bytes
        assert_eq!(1, buf.len());
        assert_eq!(contents[0..1], buf[0..]);

        let num_bytes_result_ptr = &mut 0u64;

        assert_eq!(0, unsafe {
            num_unsealed_bytes(storage, access, num_bytes_result_ptr)
        });

        // ensure that our byte-counting function works
        assert_eq!(buf.len(), *num_bytes_result_ptr as usize);
    }
}
