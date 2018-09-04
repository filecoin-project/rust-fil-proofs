use api::util;
use api::{SectorAccess, StatusCode};
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

/// Initializes and returns a DiskBackedStorage, used to dispense sector access.
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
) -> *mut DiskBackedStorage {
    let storage = DiskBackedStorage {
        sealed_path: String::from(util::str_from_c(sealed_dir_path)),
        staging_path: String::from(util::str_from_c(staging_dir_path)),
    };

    Box::into_raw(Box::new(storage))
}

/// Destroys a disk backed storage by freeing its memory.
///
/// # Arguments
///
/// * `ptr` - pointer to a DiskBackedStorage
/// ```
#[no_mangle]
pub unsafe extern "C" fn destroy_disk_backed_storage(ptr: *mut DiskBackedStorage) -> () {
    let _ = Box::from_raw(ptr);
}

/// Returns a sector access (path) in the sealed area.
///
/// # Arguments
///
/// * `ptr` - pointer to a DiskBackedStorage
/// ```
#[no_mangle]
pub unsafe extern "C" fn new_sealed_sector_access(ptr: *mut DiskBackedStorage) -> SectorAccess {
    let dbs = util::cast_const(ptr);
    let path = Path::new(&dbs.sealed_path);
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

/// Returns a sector access (path) in the staging area.
///
/// # Arguments
///
/// * `ptr` - pointer to a DiskBackedStorage
/// ```
#[no_mangle]
pub unsafe extern "C" fn new_staging_sector_access(ptr: *mut DiskBackedStorage) -> SectorAccess {
    let dbs = util::cast_const(ptr);
    let path = Path::new(&dbs.staging_path);
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

/// Appends some bytes to a file using `access` as its path and returns a status code indicating
/// success or failure.
///
/// # Arguments
///
/// * `_dbs_ptr`   - pointer to a DiskBackedStorage
/// * `access`     - an unsealed sector access (path)
/// * `data_ptr`   - pointer to data_len-length array of bytes to write
/// * `data_len`   - number of items in the data_ptr array
/// * `result_ptr` - pointer to a u64, mutated by write_unsealed in order to communicate the number
///                  of bytes that were written to the access path
/// ```
#[no_mangle]
pub unsafe extern "C" fn write_unsealed(
    _dbs_ptr: *mut DiskBackedStorage,
    access: *const libc::c_char,
    data_ptr: *const u8,
    data_len: libc::size_t,
    result_ptr: *mut u64,
) -> StatusCode {
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

/// Changes the size of the unsealed sector-file with path `access`.
///
/// This function will produce an error if no file with path access exists.
///
/// TODO: This function could disappear if we move metadata <--> file sync into Rust.
///
/// # Arguments
///
/// * `_dbs_ptr` - pointer to a DiskBackedStorage
/// * `access`   - an unsealed sector access (path)
/// * `size`     - desired number of bytes to truncate to
/// ```
#[no_mangle]
pub unsafe extern "C" fn truncate_unsealed(
    _dbs_ptr: *mut DiskBackedStorage,
    access: *const libc::c_char,
    size: u64,
) -> StatusCode {
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

/// Computes the number of bytes in an unsealed sector, returning a status code indicating success
/// or failure.
///
/// TODO: This function could disappear if we move metadata <--> file sync into Rust.
///
/// # Arguments
///
/// * `_dbs_ptr`   - pointer to a DiskBackedStorage
/// * `access`     - an unsealed sector access (path)
/// * `result_ptr` - pointer to a u64, mutated by sizeof_unsealed in order to communicate the number
///                  of bytes that were written to the access path
/// ```
#[no_mangle]
pub unsafe extern "C" fn num_unsealed_bytes(
    _dbs_ptr: *mut DiskBackedStorage,
    access: *const libc::c_char,
    result_ptr: *mut u64,
) -> StatusCode {
    let path = String::from(util::str_from_c(access));

    match metadata(path) {
        Ok(m) => {
            result_ptr.write(m.len());

            0
        }
        Err(_) => 60,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs::{create_dir_all, File};
    use std::io::Read;
    use tempfile;

    fn rust_str_to_c_str(s: &str) -> *const libc::c_char {
        CString::new(s).unwrap().into_raw()
    }

    fn create_storage() -> *mut DiskBackedStorage {
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
        let storage: *mut DiskBackedStorage = create_storage();
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
