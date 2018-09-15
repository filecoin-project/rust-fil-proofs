use libc;
use std::slice::from_raw_parts;

pub mod disk_backed_storage;
pub mod util;

type StatusCode = u32;

pub trait SectorConfig {
    /// if true, uses something other exact bits, correct parameters, or full proofs
    fn is_fake(&self) -> bool;

    /// if provided, an artificial delay to seal
    fn simulate_delay_seconds(&self) -> Option<u32>;

    /// returns the number of bytes that will fit into a sector managed by this store
    fn max_unsealed_bytes_per_sector(&self) -> u64;
}

pub trait SectorManager {
    /// provisions a new sealed sector and reports the corresponding access
    fn new_sealed_sector_access(&self) -> Result<String, StatusCode>;

    /// provisions a new staging sector and reports the corresponding access
    fn new_staging_sector_access(&self) -> Result<String, StatusCode>;

    /// reports the number of bytes written to an unsealed sector
    fn num_unsealed_bytes(&self, access: String) -> Result<u64, StatusCode>;

    /// sets the number of bytes in an unsealed sector identified by `access`
    fn truncate_unsealed(&self, access: String, size: u64) -> Result<(), StatusCode>;

    /// writes `data` to the unsealed sector identified by `access`
    fn write_unsealed(&self, access: String, data: &[u8]) -> Result<u64, StatusCode>;
}

pub trait SectorStore {
    fn config(&self) -> &Box<SectorConfig>;
    fn manager(&self) -> &Box<SectorManager>;
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
    let sector_store = &mut *ss_ptr;

    match sector_store.manager().new_sealed_sector_access() {
        Ok(access) => {
            let ptr = util::rust_str_to_c_str(&access);

            result_ptr.write(ptr);

            0
        }
        Err(n) => n,
    }
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
    let sector_store = &mut *ss_ptr;

    match sector_store.manager().new_staging_sector_access() {
        Ok(access) => {
            let ptr = util::rust_str_to_c_str(&access);

            result_ptr.write(ptr);

            0
        }
        Err(n) => n,
    }
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
) -> StatusCode {
    let sector_store = &mut *ss_ptr;
    let data = from_raw_parts(data_ptr, data_len);

    match sector_store
        .manager()
        .write_unsealed(util::c_str_to_rust_str(access), data)
    {
        Ok(num_bytes_written) => {
            result_ptr.write(num_bytes_written);

            0
        }
        Err(n) => n,
    }
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
    let sector_store = &mut *ss_ptr;

    match sector_store
        .manager()
        .truncate_unsealed(util::c_str_to_rust_str(access), size)
    {
        Ok(_) => 0,
        Err(n) => n,
    }
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
    let sector_store = &mut *ss_ptr;

    match sector_store
        .manager()
        .num_unsealed_bytes(util::c_str_to_rust_str(access))
    {
        Ok(n) => {
            result_ptr.write(n);

            0
        }
        Err(status_code) => status_code,
    }
}

/// Produces a number corresponding to the number of bytes that can be written to one of this
/// SectorStore's unsealed sectors.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
/// * `result_ptr` - pointer to a u64, mutated by max_unsealed_bytes_per_sector to communicate back to
///                  callers the number of bytes an unsealed sector
/// ```
#[no_mangle]
pub unsafe extern "C" fn max_unsealed_bytes_per_sector(
    ss_ptr: *mut Box<SectorStore>,
    result_ptr: *mut u64,
) -> StatusCode {
    let sector_store = &mut *ss_ptr;
    let n = sector_store.config().max_unsealed_bytes_per_sector();

    result_ptr.write(n);

    0
}
