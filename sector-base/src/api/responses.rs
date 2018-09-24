use api::util;
use libc;
use std::ptr;

// TODO: libfilecoin_proofs.h and libsector_base.h will likely be consumed by
// the same program, so these names need to be unique. Alternatively, figure
// out a way to share this enum across crates in a way that won't cause
// cbindgen to fail.
#[repr(u8)]
#[derive(PartialEq, Debug)]
pub enum SBResponseStatus {
    SBSuccess = 0,
    SBUnclassifiedError = 1,
    SBCallerError = 2,
    SBReceiverError = 3,
}

pub trait ToResponseStatus {
    fn to_response_status(&self) -> SBResponseStatus;
}

///////////////////////////////////////////////////////////////////////////////
/// NewSealedSectorAccessResponse
/////////////////////////////////

#[repr(C)]
pub struct NewSealedSectorAccessResponse {
    pub status_code: SBResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_access: *const libc::c_char,
}

impl Default for NewSealedSectorAccessResponse {
    fn default() -> NewSealedSectorAccessResponse {
        NewSealedSectorAccessResponse {
            status_code: SBResponseStatus::SBSuccess,
            error_msg: ptr::null(),
            sector_access: ptr::null(),
        }
    }
}

impl Drop for NewSealedSectorAccessResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
            drop(util::str_from_c(self.sector_access));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_new_sealed_sector_access_response(
    ptr: *mut NewSealedSectorAccessResponse,
) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// NewStagingSectorAccessResponse
//////////////////////////////////

#[repr(C)]
pub struct NewStagingSectorAccessResponse {
    pub status_code: SBResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_access: *const libc::c_char,
}

impl Default for NewStagingSectorAccessResponse {
    fn default() -> NewStagingSectorAccessResponse {
        NewStagingSectorAccessResponse {
            status_code: SBResponseStatus::SBSuccess,
            error_msg: ptr::null(),
            sector_access: ptr::null(),
        }
    }
}

impl Drop for NewStagingSectorAccessResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
            drop(util::str_from_c(self.sector_access));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_new_staging_sector_access_response(
    ptr: *mut NewStagingSectorAccessResponse,
) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// WriteUnsealedResponse
/////////////////////////

#[repr(C)]
pub struct WriteUnsealedResponse {
    pub status_code: SBResponseStatus,
    pub error_msg: *const libc::c_char,
    pub num_bytes_written: u64,
}

impl Default for WriteUnsealedResponse {
    fn default() -> WriteUnsealedResponse {
        WriteUnsealedResponse {
            status_code: SBResponseStatus::SBSuccess,
            error_msg: ptr::null(),
            num_bytes_written: 0,
        }
    }
}

impl Drop for WriteUnsealedResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_write_unsealed_response(ptr: *mut WriteUnsealedResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// TruncateUnsealedResponse
////////////////////////////

#[repr(C)]
pub struct TruncateUnsealedResponse {
    pub status_code: SBResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for TruncateUnsealedResponse {
    fn default() -> TruncateUnsealedResponse {
        TruncateUnsealedResponse {
            status_code: SBResponseStatus::SBSuccess,
            error_msg: ptr::null(),
        }
    }
}

impl Drop for TruncateUnsealedResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_truncate_unsealed_response(ptr: *mut TruncateUnsealedResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// NumUnsealedBytesResponse
////////////////////////////

#[repr(C)]
pub struct NumUnsealedBytesResponse {
    pub status_code: SBResponseStatus,
    pub error_msg: *const libc::c_char,
    pub num_bytes: u64,
}

impl Default for NumUnsealedBytesResponse {
    fn default() -> NumUnsealedBytesResponse {
        NumUnsealedBytesResponse {
            status_code: SBResponseStatus::SBSuccess,
            error_msg: ptr::null(),
            num_bytes: 0,
        }
    }
}

impl Drop for NumUnsealedBytesResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_num_unsealed_bytes_response(ptr: *mut NumUnsealedBytesResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// MaxUnsealedBytesPerSectorResponse
/////////////////////////////////////

#[repr(C)]
pub struct MaxUnsealedBytesPerSectorResponse {
    pub status_code: SBResponseStatus,
    pub error_msg: *const libc::c_char,
    pub num_bytes: u64,
}

impl Default for MaxUnsealedBytesPerSectorResponse {
    fn default() -> MaxUnsealedBytesPerSectorResponse {
        MaxUnsealedBytesPerSectorResponse {
            status_code: SBResponseStatus::SBSuccess,
            error_msg: ptr::null(),
            num_bytes: 0,
        }
    }
}

impl Drop for MaxUnsealedBytesPerSectorResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_max_unsealed_bytes_per_sector_response(
    ptr: *mut MaxUnsealedBytesPerSectorResponse,
) {
    let _ = Box::from_raw(ptr);
}
