use crate::api::responses::*;
use crate::api::sector_store::SectorStore;
use ffi_toolkit::{c_str_to_rust_str, rust_str_to_c_str};
use libc;
use std::mem;
use std::slice::from_raw_parts;

pub mod disk_backed_storage;
pub mod errors;
pub mod responses;
pub mod sector_store;
pub mod util;

/// Returns a sector access in the sealed area.
///
/// # Arguments
///
/// * `ss_ptr` - pointer to a boxed SectorStore
#[no_mangle]
pub unsafe extern "C" fn new_sealed_sector_access(
    ss_ptr: *mut Box<SectorStore>,
) -> *mut responses::NewSealedSectorAccessResponse {
    let mut response: responses::NewSealedSectorAccessResponse = Default::default();

    let result = (*ss_ptr).manager().new_sealed_sector_access();

    match result {
        Ok(access) => {
            response.status_code = SBResponseStatus::SBNoError;
            response.sector_access = rust_str_to_c_str(access);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err.into());
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    Box::into_raw(Box::new(response))
}

/// Returns a sector access (path) in the staging area.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
#[no_mangle]
pub unsafe extern "C" fn new_staging_sector_access(
    ss_ptr: *mut Box<SectorStore>,
) -> *mut responses::NewStagingSectorAccessResponse {
    let mut response: responses::NewStagingSectorAccessResponse = Default::default();

    let result = (*ss_ptr).manager().new_staging_sector_access();

    match result {
        Ok(access) => {
            response.status_code = SBResponseStatus::SBNoError;
            response.sector_access = rust_str_to_c_str(access);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err.into());
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    Box::into_raw(Box::new(response))
}

/// Appends some bytes to an unsealed sector identified by `access` and returns the number of bytes
/// written to the unsealed sector access. Bytes written in this way are guaranteed to leave the entire
/// unsealed sector correctly preprocessed after each write.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
/// * `access`     - an unsealed sector access
/// * `data_ptr`   - pointer to data_len-length array of bytes to write
/// * `data_len`   - number of items in the data_ptr array
#[no_mangle]
pub unsafe extern "C" fn write_and_preprocess(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
    data_ptr: *const u8,
    data_len: libc::size_t,
) -> *mut responses::WriteAndPreprocessResponse {
    let mut response: responses::WriteAndPreprocessResponse = Default::default();

    let data = from_raw_parts(data_ptr, data_len);

    let result = (*ss_ptr)
        .manager()
        .write_and_preprocess(c_str_to_rust_str(access).to_string(), data);

    match result {
        Ok(num_data_bytes_written) => {
            if num_data_bytes_written != data_len as u64 {
                response.status_code = SBResponseStatus::SBReceiverError;
                response.error_msg = rust_str_to_c_str(format!(
                    "expected to write {}-bytes, but wrote {}-bytes",
                    data_len as u64, num_data_bytes_written
                ));
            } else {
                response.status_code = SBResponseStatus::SBNoError;
                response.num_bytes_written = num_data_bytes_written;
            }
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err.into());
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    Box::into_raw(Box::new(response))
}

/// Changes the size of the unsealed sector identified by `access`.
///
/// # Arguments
///
/// * `ss_ptr` - pointer to a boxed SectorStore
/// * `access` - an unsealed sector access
/// * `size`   - desired number of bytes to truncate to
#[no_mangle]
pub unsafe extern "C" fn truncate_unsealed(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
    size: u64,
) -> *mut responses::TruncateUnsealedResponse {
    let mut response: responses::TruncateUnsealedResponse = Default::default();

    let result = (*ss_ptr)
        .manager()
        .truncate_unsealed(c_str_to_rust_str(access).to_string(), size);

    match result {
        Ok(_) => {
            response.status_code = SBResponseStatus::SBNoError;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err.into());
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    Box::into_raw(Box::new(response))
}

/// Reads `num_bytes` bytes from `access`, starting from `start_offset`.
/// * `access` must contain raw, unpreprocessed data – as written by `get_unsealed` or `get_unsealed_range`.
#[no_mangle]
pub unsafe extern "C" fn read_raw(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
    start_offset: u64,
    num_bytes: u64,
) -> *mut responses::ReadRawResponse {
    let mut response: responses::ReadRawResponse = Default::default();

    let result = (*ss_ptr).manager().read_raw(
        c_str_to_rust_str(access).to_string(),
        start_offset,
        num_bytes,
    );

    match result {
        Ok(data) => {
            response.status_code = SBResponseStatus::SBNoError;
            response.data_ptr = data.as_ptr();
            response.data_len = data.len();
            mem::forget(data);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err.into());
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    Box::into_raw(Box::new(response))
}

/// Computes the number of bytes in an unsealed sector identified by `access`.
///
/// TODO: This function could disappear if we move metadata <--> file sync into Rust.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
/// * `access`     - an unsealed sector access
#[no_mangle]
pub unsafe extern "C" fn num_unsealed_bytes(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
) -> *mut responses::NumUnsealedBytesResponse {
    let mut response: responses::NumUnsealedBytesResponse = Default::default();

    let result = (*ss_ptr)
        .manager()
        .num_unsealed_bytes(c_str_to_rust_str(access).to_string());

    match result {
        Ok(n) => {
            response.status_code = SBResponseStatus::SBNoError;
            response.num_bytes = n;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err.into());
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    Box::into_raw(Box::new(response))
}

/// Returns the maximum number of unsealed (original) bytes which can be written to an unsealed
/// sector managed by this SectorStore.
///
/// # Arguments
///
/// * `ss_ptr`     - pointer to a boxed SectorStore
#[no_mangle]
pub unsafe extern "C" fn max_unsealed_bytes_per_sector(
    ss_ptr: *mut Box<SectorStore>,
) -> *mut responses::MaxUnsealedBytesPerSectorResponse {
    let mut response: responses::MaxUnsealedBytesPerSectorResponse = Default::default();

    response.status_code = SBResponseStatus::SBNoError;
    response.num_bytes = (*ss_ptr).config().max_unsealed_bytes_per_sector();

    Box::into_raw(Box::new(response))
}
