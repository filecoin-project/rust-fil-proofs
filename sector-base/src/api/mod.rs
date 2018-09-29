use api::responses::SBResponseStatus;
use api::responses::ToResponseStatus;
use api::SectorManagerErr::CallerError;
use api::SectorManagerErr::ReceiverError;
use api::SectorManagerErr::UnclassifiedError;
use libc;
use std::ffi::CString;
use std::mem;
use std::slice::from_raw_parts;

pub mod disk_backed_storage;
pub mod responses;
pub mod util;

#[derive(Debug)]
pub enum SectorManagerErr {
    UnclassifiedError(String),
    CallerError(String),
    ReceiverError(String),
}

impl<T> ToResponseStatus for Result<T, SectorManagerErr> {
    fn to_response_status(&self) -> SBResponseStatus {
        match self {
            Ok(_) => SBResponseStatus::SBSuccess,
            Err(s_m_err) => match s_m_err {
                UnclassifiedError(_) => SBResponseStatus::SBUnclassifiedError,
                CallerError(_) => SBResponseStatus::SBCallerError,
                ReceiverError(_) => SBResponseStatus::SBReceiverError,
            },
        }
    }
}

pub trait SectorConfig {
    /// if true, uses something other exact bits, correct parameters, or full proofs
    fn is_fake(&self) -> bool;

    /// if provided, an artificial delay to seal
    fn simulate_delay_seconds(&self) -> Option<u32>;

    /// returns the number of bytes that will fit into a sector managed by this store
    fn max_unsealed_bytes_per_sector(&self) -> u64;

    /// returns the number of bytes in a sealed sector managed by this store
    fn sector_bytes(&self) -> u64;

    /// We need a distinguished place to cache 'the' parameters corresponding to the SetupParams
    /// currently being used. These are only easily generated at replication time but need to be
    /// accessed at verification time too.
    fn dummy_parameter_cache_name(&self) -> String;
}

pub trait SectorManager {
    /// provisions a new sealed sector and reports the corresponding access
    fn new_sealed_sector_access(&self) -> Result<String, SectorManagerErr>;

    /// provisions a new staging sector and reports the corresponding access
    fn new_staging_sector_access(&self) -> Result<String, SectorManagerErr>;

    /// reports the number of bytes written to an unsealed sector
    fn num_unsealed_bytes(&self, access: String) -> Result<u64, SectorManagerErr>;

    /// sets the number of bytes in an unsealed sector identified by `access`
    fn truncate_unsealed(&self, access: String, size: u64) -> Result<(), SectorManagerErr>;

    /// writes `data` to the staging sector identified by `access`, incrementally preprocessing `access`
    fn write_and_preprocess(&self, access: String, data: &[u8]) -> Result<u64, SectorManagerErr>;

    fn read_raw(
        &self,
        access: String,
        start_offset: u64,
        numb_bytes: u64,
    ) -> Result<Vec<u8>, SectorManagerErr>;
}

pub trait SectorStore {
    fn config(&self) -> &SectorConfig;
    fn manager(&self) -> &SectorManager;
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

    response.status_code = result.to_response_status();

    match result {
        Ok(access) => {
            let msg = CString::new(access).unwrap();
            response.sector_access = msg.as_ptr();
            mem::forget(msg);
        }
        Err(err) => {
            let msg = CString::new(format!("{:?}", err)).unwrap();
            response.error_msg = msg.as_ptr();
            mem::forget(msg);
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

    response.status_code = result.to_response_status();

    match result {
        Ok(access) => {
            let msg = CString::new(access).unwrap();
            response.sector_access = msg.as_ptr();
            mem::forget(msg);
        }
        Err(err) => {
            let msg = CString::new(format!("{:?}", err)).unwrap();
            response.error_msg = msg.as_ptr();
            mem::forget(msg);
        }
    }

    Box::into_raw(Box::new(response))
}

/// Appends some bytes to an unsealed sector identified by `access` and returns the number of bytes
/// written to the unsealed sector access.
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
        .write_and_preprocess(util::c_str_to_rust_str(access), data);

    response.status_code = result.to_response_status();

    match result {
        Ok(num_data_bytes_written) => {
            if num_data_bytes_written != data_len as u64 {
                response.status_code = SBResponseStatus::SBReceiverError;

                let msg = CString::new(format!(
                    "expected to write {}-bytes, but wrote {}-bytes",
                    data_len as u64, num_data_bytes_written
                )).unwrap();
                response.error_msg = msg.as_ptr();
                mem::forget(msg);
            }

            response.num_bytes_written = num_data_bytes_written;
        }
        Err(err) => {
            let msg = CString::new(format!("{:?}", err)).unwrap();
            response.error_msg = msg.as_ptr();
            mem::forget(msg);
        }
    }

    Box::into_raw(Box::new(response))
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
#[no_mangle]
pub unsafe extern "C" fn truncate_unsealed(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
    size: u64,
) -> *mut responses::TruncateUnsealedResponse {
    let mut response: responses::TruncateUnsealedResponse = Default::default();

    let result = (*ss_ptr)
        .manager()
        .truncate_unsealed(util::c_str_to_rust_str(access), size);

    response.status_code = result.to_response_status();

    match result {
        Ok(_) => {}
        Err(err) => {
            let msg = CString::new(format!("{:?}", err)).unwrap();
            response.error_msg = msg.as_ptr();
            mem::forget(msg);
        }
    }

    Box::into_raw(Box::new(response))
}

#[no_mangle]
pub unsafe extern "C" fn read_raw(
    ss_ptr: *mut Box<SectorStore>,
    access: *const libc::c_char,
    start_offset: u64,
    num_bytes: u64,
) -> *mut responses::ReadRawResponse {
    let mut response: responses::ReadRawResponse = Default::default();

    let result =
        (*ss_ptr)
            .manager()
            .read_raw(util::c_str_to_rust_str(access), start_offset, num_bytes);

    response.status_code = result.to_response_status();

    match result {
        Ok(data) => {
            response.data_ptr = data.as_ptr();
            response.data_len = data.len();
            mem::forget(data);
        }
        Err(err) => {
            let msg = CString::new(format!("{:?}", err)).unwrap();
            response.error_msg = msg.as_ptr();
            mem::forget(msg);
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
        .num_unsealed_bytes(util::c_str_to_rust_str(access));

    response.status_code = result.to_response_status();

    match result {
        Ok(n) => {
            response.num_bytes = n;
        }
        Err(err) => {
            let msg = CString::new(format!("{:?}", err)).unwrap();
            response.error_msg = msg.as_ptr();
            mem::forget(msg);
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

    response.num_bytes = (*ss_ptr).config().max_unsealed_bytes_per_sector();

    Box::into_raw(Box::new(response))
}
