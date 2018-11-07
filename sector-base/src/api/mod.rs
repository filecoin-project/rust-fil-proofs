use api::disk_backed_storage::ConfiguredStore;
use api::errors::SectorBuilderErr;
use api::errors::SectorBuilderErr::*;
use api::errors::SectorManagerErr;
use api::responses::*;
use api::sector_builder::SectorBuilder;
use api::sector_store::{SectorManager, SectorStore};
use ffi_toolkit::{c_str_to_rust_str, raw_ptr, rust_str_to_c_str};
use libc;
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::mem;
use std::slice::from_raw_parts;

pub mod disk_backed_storage;
pub mod errors;
pub mod responses;
pub mod sector_builder;
pub mod sector_store;
pub mod util;

/// Initializes and returns a SectorBuilder.
///
#[no_mangle]
pub unsafe extern "C" fn init_sector_builder(
    sector_store_config_ptr: *const ConfiguredStore,
    last_used_sector_id: u64,
    metadata_dir: *const libc::c_char,
    prover_id: &[u8; 31],
    sealed_sector_dir: *const libc::c_char,
    staged_sector_dir: *const libc::c_char,
) -> *mut responses::InitSectorBuilderResponse {
    let mut response: responses::InitSectorBuilderResponse = Default::default();

    if let Some(cfg) = sector_store_config_ptr.as_ref() {
        match SectorBuilder::init_from_metadata(
            cfg,
            last_used_sector_id,
            c_str_to_rust_str(metadata_dir).to_string(),
            *prover_id,
            c_str_to_rust_str(sealed_sector_dir).to_string(),
            c_str_to_rust_str(staged_sector_dir).to_string(),
        ) {
            Ok(sb) => {
                response.status_code = responses::SBResponseStatus::SBNoError;
                response.sector_builder = raw_ptr(sb);
            }
            Err(err) => {
                let (code, ptr) = err_code_and_msg(&err);
                response.status_code = code;
                response.error_msg = ptr;
            }
        }
    } else {
        response.status_code = SBResponseStatus::SBCallerError;

        let msg = CString::new("caller did not provide ConfiguredStore").unwrap();
        response.error_msg = msg.as_ptr();
        mem::forget(msg);
    }

    raw_ptr(response)
}

/// Destroys a SectorBuilder.
///
#[no_mangle]
pub unsafe extern "C" fn destroy_sector_builder(ptr: *mut SectorBuilder) {
    let _ = Box::from_raw(ptr);
}

/// Writes user piece-bytes to a staged sector and returns the id of the sector
/// to which the bytes were written.
///
#[no_mangle]
pub unsafe extern "C" fn add_piece(
    ptr: *mut SectorBuilder,
    piece_key: *const libc::c_char,
    piece_ptr: *const u8,
    piece_len: libc::size_t,
) -> *mut responses::AddPieceResponse {
    let piece_key = c_str_to_rust_str(piece_key);
    let piece_bytes = from_raw_parts(piece_ptr, piece_len);

    let mut response: responses::AddPieceResponse = Default::default();

    match (*ptr).add_piece(piece_key, piece_bytes) {
        Ok(sector_id) => {
            response.status_code = SBResponseStatus::SBNoError;
            response.sector_id = sector_id;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    Box::into_raw(Box::new(response))
}

/// Returns the number of user bytes that will fit into a staged sector.
///
#[no_mangle]
pub unsafe extern "C" fn get_max_user_bytes_per_staged_sector(
    ptr: *mut SectorBuilder,
) -> *mut responses::GetMaxStagedBytesPerSector {
    let mut response: responses::GetMaxStagedBytesPerSector = Default::default();

    response.status_code = SBResponseStatus::SBNoError;
    response.max_staged_bytes_per_sector = (*ptr).get_max_user_bytes_per_staged_sector();;

    Box::into_raw(Box::new(response))
}

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
            response.status_code = responses::SBResponseStatus::SBNoError;
            response.sector_access = rust_str_to_c_str(&access);
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
            response.status_code = responses::SBResponseStatus::SBNoError;
            response.sector_access = rust_str_to_c_str(&access);
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
                response.status_code = responses::SBResponseStatus::SBReceiverError;
                response.error_msg = rust_str_to_c_str(&format!(
                    "expected to write {}-bytes, but wrote {}-bytes",
                    data_len as u64, num_data_bytes_written
                ));
            } else {
                response.status_code = responses::SBResponseStatus::SBNoError;
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
