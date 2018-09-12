use std::borrow::Cow;
use std::ffi::CStr;
use std::path::PathBuf;

use libc;
use rand::{thread_rng, Rng};

pub mod disk_backed_storage;

type SectorAccess = *const libc::c_char;
type StatusCode = u32;

pub trait SectorStore {
    /// if true, uses something other exact bits, correct parameters, or full proofs
    unsafe fn is_fake(&self) -> bool;

    /// if true, an artificial delay to seal
    unsafe fn simulate_delay(&self) -> bool;

    /// returns the number of bytes that will fit into a sector managed by this store
    unsafe fn num_bytes_per_sector(&self) -> u64;

    /// provisions a new sealed sector and writes the corresponding access to `result_ptr`
    unsafe fn new_sealed_sector_access(&self, result_ptr: *mut *const libc::c_char) -> StatusCode;

    /// provisions a new staging sector and writes the corresponding access to `result_ptr`
    unsafe fn new_staging_sector_access(&self, result_ptr: *mut *const libc::c_char) -> StatusCode;

    /// reports the number of bytes written to an unsealed sector
    unsafe fn num_unsealed_bytes(&self, access: SectorAccess, result_ptr: *mut u64) -> StatusCode;

    /// sets the number of bytes in an unsealed sector identified by `access`
    unsafe fn truncate_unsealed(&self, access: SectorAccess, size: u64) -> StatusCode;

    /// writes `data_len` bytes from `data_ptr` to the unsealed sector identified by `access`
    unsafe fn write_unsealed(
        &self,
        access: *const libc::c_char,
        data_ptr: *const u8,
        data_len: libc::size_t,
        result_ptr: *mut u64,
    ) -> StatusCode;
}

/// Destroys a boxed SectorStore by freeing its memory.
///
/// # Arguments
///
/// * `ss_ptr` - pointer to a boxed SectorStore
///
#[no_mangle]
pub unsafe extern "C" fn destroy_storage(ss_ptr: *mut Box<SectorStore>) -> StatusCode {
    let _ = Box::from_raw(ss_ptr);

    0
}

/// Returns a sector access in the sealed area.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
/// * `result_ptr` - pointer to location where provisioned SectorAccess will be written
/// ```
#[no_mangle]
pub unsafe extern "C" fn new_sealed_sector_access(
    ss_ptr: *mut Box<SectorStore>,
    result_ptr: *mut *const libc::c_char,
) -> StatusCode {
    let m = &mut *ss_ptr;
    m.new_sealed_sector_access(result_ptr)
}

/// Returns a sector access (path) in the staging area.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
/// * `result_ptr` - pointer to location where provisioned SectorAccess will be written
/// ```
#[no_mangle]
pub unsafe extern "C" fn new_staging_sector_access(
    ss_ptr: *mut Box<SectorStore>,
    result_ptr: *mut *const libc::c_char,
) -> StatusCode {
    let m = &mut *ss_ptr;
    m.new_staging_sector_access(result_ptr)
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
    access: SectorAccess,
    data_ptr: *const u8,
    data_len: libc::size_t,
    result_ptr: *mut u64,
) -> StatusCode {
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
    access: SectorAccess,
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
    access: SectorAccess,
    result_ptr: *mut u64,
) -> StatusCode {
    let m = &mut *ss_ptr;
    m.num_unsealed_bytes(access, result_ptr)
}

// transmutes a C string to a copy-on-write Rust string
pub unsafe fn str_from_c<'a>(x: *const libc::c_char) -> Cow<'a, str> {
    use std::borrow::Cow;
    if x.is_null() {
        Cow::from("")
    } else {
        CStr::from_ptr(x).to_string_lossy()
    }
}
// creates a string of size len containing uppercase alpha-chars
pub fn rand_alpha_string(len: u8) -> String {
    let mut str = String::new();
    let mut rng = thread_rng();

    for _ in 0..len {
        let ch = rng.gen_range(b'A', b'Z') as char;
        str.push(ch);
    }

    str
}

// transmutes a C string to a PathBuf
pub unsafe fn pbuf_from_c(x: *const libc::c_char) -> PathBuf {
    PathBuf::from(String::from(str_from_c(x)))
}
