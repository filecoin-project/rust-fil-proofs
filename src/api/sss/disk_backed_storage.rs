use api::sss::SectorStore;
use api::util;
use libc;
use std::ffi::CString;
use std::fs::{create_dir_all, metadata, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::forget;
use std::path::Path;
use std::slice;

pub struct DiskBackedStorage {
    staging_path: String,
    sealed_path: String,
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
        sealed_path: String::from(util::str_from_c(sealed_dir_path)),
        staging_path: String::from(util::str_from_c(staging_dir_path)),
    };

    Box::into_raw(Box::new(Box::new(m)))
}

impl SectorStore for DiskBackedStorage {
    unsafe fn new_sealed_sector_access(&self) -> *const libc::c_char {
        let path = Path::new(&self.sealed_path);
        let pbuf = path.join(util::rand_alpha_string(32));

        let create_result = match create_dir_all(&path) {
            Ok(_) => match File::create(&pbuf) {
                Ok(_) => 0,
                Err(_) => 71,
            },
            Err(_) => 70,
        };

        // TODO: remove this as soon as function is modified to return a status
        // code instead of a string
        assert_eq!(create_result, 0, "failed to create file");

        let c_string = CString::new(pbuf.to_str().unwrap()).unwrap();
        let ptr = c_string.as_ptr();

        forget(c_string);

        ptr
    }

    unsafe fn new_staging_sector_access(&self) -> *const libc::c_char {
        let path = Path::new(&self.staging_path);
        let pbuf = path.join(util::rand_alpha_string(32));

        let create_result = match create_dir_all(&path) {
            Ok(_) => match File::create(&pbuf) {
                Ok(_) => 0,
                Err(_) => 81,
            },
            Err(_) => 80,
        };

        // TODO: remove this as soon as function is modified to return a status
        // code instead of a string
        assert_eq!(create_result, 0, "failed to create file");

        let c_string = CString::new(pbuf.to_str().unwrap()).unwrap();
        let ptr = c_string.as_ptr();

        forget(c_string);

        ptr
    }

    unsafe fn num_unsealed_bytes(&self, access: *const libc::c_char, result_ptr: *mut u64) -> u8 {
        let path = String::from(util::str_from_c(access));

        match metadata(path) {
            Ok(m) => {
                result_ptr.write(m.len());

                0
            }
            Err(_) => 60,
        }
    }

    unsafe fn truncate_unsealed(&self, access: *const libc::c_char, size: u64) -> u8 {
        let path = String::from(util::str_from_c(access));

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
    ) -> u8 {
        let data = slice::from_raw_parts(data_ptr as *const u8, data_len as usize);

        let path = String::from(util::str_from_c(access));

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
    use super::*;
    use api::sss::disk_backed_storage::init_disk_backed_storage;
    use api::sss::{
        new_staging_sector_access, num_unsealed_bytes, truncate_unsealed, write_unsealed,
    };
    use api::util;
    use api::SectorAccess;
    use std::ffi::CString;
    use std::fs::{create_dir_all, File};
    use std::io::Read;
    use tempfile;

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
        let pbuf = unsafe { util::pbuf_from_c(access) };
        let mut file = File::open(pbuf).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    #[test]
    fn unsealed_sector_write_and_truncate() {
        let storage = create_storage();
        let access = unsafe { new_staging_sector_access(storage) };

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
