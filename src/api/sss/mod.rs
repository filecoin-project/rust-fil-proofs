pub mod disk_backed_storage;

use api::StatusCode;
use libc;

pub trait SectorStore {
    unsafe fn new_sealed_sector_access(&self) -> *const libc::c_char;
    unsafe fn new_staging_sector_access(&self) -> *const libc::c_char;
    unsafe fn num_unsealed_bytes(&self, access: *const libc::c_char, result_ptr: *mut u64) -> u8;
    unsafe fn truncate_unsealed(&self, access: *const libc::c_char, size: u64) -> u8;
    unsafe fn write_unsealed(
        &self,
        access: *const libc::c_char,
        data_ptr: *const u8,
        data_len: libc::size_t,
        result_ptr: *mut u64,
    ) -> u8;
}

/// Destroys a boxed SectorStore by freeing its memory.
///
/// # Arguments
///
/// * `ss_ptr` - pointer to a boxed SectorStore
/// ```
#[no_mangle]
pub unsafe extern "C" fn destroy_storage(ss_ptr: *mut Box<SectorStore>) -> () {
    let _ = Box::from_raw(ss_ptr);
}

/// Returns a sector access in the sealed area.
///
/// # Arguments
///
/// * `ss_ptr` - pointer to a boxed SectorStore
/// ```
#[no_mangle]
pub unsafe extern "C" fn new_sealed_sector_access(
    ss_ptr: *mut Box<SectorStore>,
) -> *const libc::c_char {
    let m = &mut *ss_ptr;
    m.new_sealed_sector_access()
}

/// Returns a sector access (path) in the staging area.
///
/// # Arguments
///
/// * `ptr` - pointer to a boxed SectorStore
/// ```
#[no_mangle]
pub unsafe extern "C" fn new_staging_sector_access(
    ss_ptr: *mut Box<SectorStore>,
) -> *const libc::c_char {
    let m = &mut *ss_ptr;
    m.new_staging_sector_access()
}

/// Appends some bytes to an unsealed sector identified by `access` and returns a status code
/// indicating success or failure.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
/// * `access`     - an unsealed sector access
/// * `data_ptr`   - pointer to data_len-length array of bytes to write
/// * `data_len`   - number of items in the data_ptr array
/// * `result_ptr` - pointer to a u64, mutated by write_unsealed in order to communicate the number
///                  of bytes that were written to the unsealed sector
/// ```
#[no_mangle]
pub unsafe extern "C" fn write_unsealed(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
    data_ptr: *const u8,
    data_len: libc::size_t,
    result_ptr: *mut u64,
) -> u8 {
    let m = &mut *ss_ptr;
    m.write_unsealed(access, data_ptr, data_len, result_ptr)
}

/// Changes the size of the unsealed sector identified by `access`.
///
/// TODO: This function could disappear if we move metadata <--> file sync into Rust.
///
/// # Arguments
///
/// * `ss_ptr` - pointer to a boxed SectorStore
/// * `access` - an unsealed sector access
/// * `size`   - desired number of bytes to truncate to
/// ```
#[no_mangle]
pub unsafe extern "C" fn truncate_unsealed(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
    size: u64,
) -> StatusCode {
    let m = &mut *ss_ptr;
    m.truncate_unsealed(access, size)
}

/// Computes the number of bytes in an unsealed sector identified by `access`, returning a status
/// code indicating success or failure.
///
/// TODO: This function could disappear if we move metadata <--> file sync into Rust.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
/// * `access`     - an unsealed sector access
/// * `result_ptr` - pointer to a u64, mutated by num_unsealed_bytes to communicate back to callers
///                  the number of bytes in the unsealed sector
/// ```
#[no_mangle]
pub unsafe extern "C" fn num_unsealed_bytes(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
    result_ptr: *mut u64,
) -> StatusCode {
    let m = &mut *ss_ptr;
    m.num_unsealed_bytes(access, result_ptr)
}
