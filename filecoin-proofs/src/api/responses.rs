use api::util;
use libc;
use std::ptr;

// TODO: libfilecoin_proofs.h and libsector_base.h will likely be consumed by
// the same program, so these names need to be unique. Alternatively, figure
// out a way to share this enum across crates in a way that won't cause
// cbindgen to fail.
#[repr(u8)]
#[derive(PartialEq, Debug)]
pub enum FCPResponseStatus {
    FCPSuccess = 0,
    FCPUnclassifiedError = 1,
    FCPCallerError = 2,
    FCPReceiverError = 3,
}

///////////////////////////////////////////////////////////////////////////////
/// SealResponse
////////////////

#[repr(C)]
pub struct SealResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub comm_r_star: [u8; 32],
    pub proof: [u8; 192],
}

impl Default for SealResponse {
    fn default() -> SealResponse {
        SealResponse {
            status_code: FCPResponseStatus::FCPSuccess,
            error_msg: ptr::null(),
            comm_d: [0; 32],
            comm_r: [0; 32],
            comm_r_star: [0; 32],
            proof: [0; 192],
        }
    }
}

impl Drop for SealResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_seal_response(ptr: *mut SealResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// VerifySealResponse
//////////////////////

#[repr(C)]
pub struct VerifySealResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifySealResponse {
    fn default() -> VerifySealResponse {
        VerifySealResponse {
            status_code: FCPResponseStatus::FCPSuccess,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

impl Drop for VerifySealResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_verify_seal_response(ptr: *mut VerifySealResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// GetUnsealedRangeResponse
////////////////////////////

#[repr(C)]
pub struct GetUnsealedRangeResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub num_bytes_written: u64,
}

impl Default for GetUnsealedRangeResponse {
    fn default() -> GetUnsealedRangeResponse {
        GetUnsealedRangeResponse {
            status_code: FCPResponseStatus::FCPSuccess,
            error_msg: ptr::null(),
            num_bytes_written: 0,
        }
    }
}

impl Drop for GetUnsealedRangeResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_get_unsealed_range_response(ptr: *mut GetUnsealedRangeResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// GetUnsealedResponse
///////////////////////

#[repr(C)]
pub struct GetUnsealedResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for GetUnsealedResponse {
    fn default() -> GetUnsealedResponse {
        GetUnsealedResponse {
            status_code: FCPResponseStatus::FCPSuccess,
            error_msg: ptr::null(),
        }
    }
}

impl Drop for GetUnsealedResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_get_unsealed_response(ptr: *mut GetUnsealedResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// GeneratePoSTResult
//////////////////////

#[repr(C)]
pub struct GeneratePoSTResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub faults_len: libc::size_t,
    pub faults_ptr: *const u8,
    pub proof: [u8; 192],
}

impl Default for GeneratePoSTResponse {
    fn default() -> GeneratePoSTResponse {
        GeneratePoSTResponse {
            status_code: FCPResponseStatus::FCPSuccess,
            error_msg: ptr::null(),
            faults_len: 0,
            faults_ptr: ptr::null(),
            proof: [0; 192],
        }
    }
}

impl Drop for GeneratePoSTResponse {
    fn drop(&mut self) {
        unsafe {
            drop(Vec::from_raw_parts(
                self.faults_ptr as *mut u8,
                self.faults_len,
                self.faults_len,
            ));

            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_generate_post_response(ptr: *mut GeneratePoSTResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// VerifyPoSTResult
////////////////////

#[repr(C)]
pub struct VerifyPoSTResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifyPoSTResponse {
    fn default() -> VerifyPoSTResponse {
        VerifyPoSTResponse {
            status_code: FCPResponseStatus::FCPSuccess,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

impl Drop for VerifyPoSTResponse {
    fn drop(&mut self) {
        unsafe {
            drop(util::str_from_c(self.error_msg));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_verify_post_response(ptr: *mut VerifyPoSTResponse) {
    let _ = Box::from_raw(ptr);
}
