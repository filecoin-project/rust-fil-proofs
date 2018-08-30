use api::util;
use api::SectorAccess;
use libc;
use std::ffi::CString;
use std::mem::forget;
use std::path::Path;

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

    let c_string = CString::new(pbuf.to_str().unwrap()).unwrap();
    let ptr = c_string.as_ptr();

    forget(c_string);

    ptr
}
