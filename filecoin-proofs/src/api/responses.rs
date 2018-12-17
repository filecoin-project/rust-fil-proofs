use crate::api::sector_builder::errors::SectorBuilderErr;
use crate::api::sector_builder::SectorBuilder;
use crate::api::{API_POREP_PROOF_BYTES, API_POST_PROOF_BYTES};
use failure::Error;
use ffi_toolkit::free_c_str;
use libc;
use sector_base::api::errors::SectorManagerErr;
use std::ffi::CString;
use std::mem;
use std::ptr;

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FCPResponseStatus {
    // Don't use FCPSuccess, since that complicates description of 'successful' verification.
    FCPNoError = 0,
    FCPUnclassifiedError = 1,
    FCPCallerError = 2,
    FCPReceiverError = 3,
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FFISealStatus {
    Sealed = 0,
    Pending = 1,
    Failed = 2,
    Sealing = 3,
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
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

impl Drop for VerifySealResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_verify_seal_response(ptr: *mut VerifySealResponse) {
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
    pub faults_ptr: *const u64,
    pub proof: [u8; API_POST_PROOF_BYTES],
}

impl Default for GeneratePoSTResponse {
    fn default() -> GeneratePoSTResponse {
        GeneratePoSTResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            faults_len: 0,
            faults_ptr: ptr::null(),
            proof: [0; API_POST_PROOF_BYTES],
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

            free_c_str(self.error_msg as *mut libc::c_char);
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
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

impl Drop for VerifyPoSTResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_verify_post_response(ptr: *mut VerifyPoSTResponse) {
    let _ = Box::from_raw(ptr);
}

// err_code_and_msg accepts an Error struct and produces a tuple of response
// status code and a pointer to a C string, both of which can be used to set
// fields in a response struct to be returned from an FFI call.
pub fn err_code_and_msg(err: &Error) -> (FCPResponseStatus, *const libc::c_char) {
    use crate::api::responses::FCPResponseStatus::*;

    let msg = CString::new(format!("{}", err)).unwrap();
    let ptr = msg.as_ptr();
    mem::forget(msg);

    match err.downcast_ref() {
        Some(SectorBuilderErr::OverflowError { .. }) => return (FCPCallerError, ptr),
        Some(SectorBuilderErr::IncompleteWriteError { .. }) => return (FCPReceiverError, ptr),
        Some(SectorBuilderErr::Unrecoverable(_, _)) => return (FCPReceiverError, ptr),
        Some(SectorBuilderErr::PieceNotFound(_)) => return (FCPCallerError, ptr),
        None => (),
    }

    match err.downcast_ref() {
        Some(SectorManagerErr::UnclassifiedError(_)) => return (FCPUnclassifiedError, ptr),
        Some(SectorManagerErr::CallerError(_)) => return (FCPCallerError, ptr),
        Some(SectorManagerErr::ReceiverError(_)) => return (FCPReceiverError, ptr),
        None => (),
    }

    (FCPUnclassifiedError, ptr)
}

///////////////////////////////////////////////////////////////////////////////
/// InitSectorBuilderResponse
/////////////////////////////

#[repr(C)]
pub struct InitSectorBuilderResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_builder: *mut SectorBuilder,
}

impl Default for InitSectorBuilderResponse {
    fn default() -> InitSectorBuilderResponse {
        InitSectorBuilderResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_builder: ptr::null_mut(),
        }
    }
}

impl Drop for InitSectorBuilderResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_init_sector_builder_response(ptr: *mut InitSectorBuilderResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// AddPieceResponse
////////////////////

#[repr(C)]
pub struct AddPieceResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub sector_id: u64,
}

impl Default for AddPieceResponse {
    fn default() -> AddPieceResponse {
        AddPieceResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sector_id: 0,
        }
    }
}

impl Drop for AddPieceResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_add_piece_response(ptr: *mut AddPieceResponse) {
    let _ = Box::from_raw(ptr);
}

////////////////////////////////////////////////////////////////////////////////
/// ReadPieceFromSealedSectorResponse
/////////////////////////////////////

#[repr(C)]
pub struct ReadPieceFromSealedSectorResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub data_len: libc::size_t,
    pub data_ptr: *const u8,
}

impl Default for ReadPieceFromSealedSectorResponse {
    fn default() -> ReadPieceFromSealedSectorResponse {
        ReadPieceFromSealedSectorResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            data_len: 0,
            data_ptr: ptr::null(),
        }
    }
}

impl Drop for ReadPieceFromSealedSectorResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);

            drop(Vec::from_raw_parts(
                self.data_ptr as *mut u8,
                self.data_len,
                self.data_len,
            ));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_read_piece_from_sealed_sector_response(
    ptr: *mut ReadPieceFromSealedSectorResponse,
) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// SealAllStagedSectorsResponse
////////////////////////////////

#[repr(C)]
pub struct SealAllStagedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for SealAllStagedSectorsResponse {
    fn default() -> SealAllStagedSectorsResponse {
        SealAllStagedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

impl Drop for SealAllStagedSectorsResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_seal_all_staged_sectors_response(
    ptr: *mut SealAllStagedSectorsResponse,
) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// GetMaxStagedBytesPerSector
//////////////////////////////

#[repr(C)]
pub struct GetMaxStagedBytesPerSector {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub max_staged_bytes_per_sector: u64,
}

impl Default for GetMaxStagedBytesPerSector {
    fn default() -> GetMaxStagedBytesPerSector {
        GetMaxStagedBytesPerSector {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            max_staged_bytes_per_sector: 0,
        }
    }
}

impl Drop for GetMaxStagedBytesPerSector {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_get_max_user_bytes_per_staged_sector_response(
    ptr: *mut GetMaxStagedBytesPerSector,
) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// GetSealStatusResponse
/////////////////////////

#[repr(C)]
pub struct GetSealStatusResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub seal_status_code: FFISealStatus,

    // sealing failed - here's the error
    pub seal_error_msg: *const libc::c_char,

    // sealed sector metadata
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub comm_r_star: [u8; 32],
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub snark_proof: [u8; API_POREP_PROOF_BYTES],
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,
}

#[repr(C)]
pub struct FFIPieceMetadata {
    pub piece_key: *const libc::c_char,
    pub num_bytes: u64,
}

impl Drop for FFIPieceMetadata {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.piece_key as *mut libc::c_char);
        }
    }
}

impl Default for GetSealStatusResponse {
    fn default() -> GetSealStatusResponse {
        GetSealStatusResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),

            seal_status_code: FFISealStatus::Failed,

            seal_error_msg: ptr::null(),

            comm_d: Default::default(),
            comm_r: Default::default(),
            comm_r_star: Default::default(),
            pieces_len: 0,
            pieces_ptr: ptr::null(),
            sector_access: ptr::null(),
            sector_id: 0,
            snark_proof: [0; 384],
        }
    }
}

impl Drop for GetSealStatusResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
            free_c_str(self.seal_error_msg as *mut libc::c_char);
            free_c_str(self.sector_access as *mut libc::c_char);
            drop(Vec::from_raw_parts(
                self.pieces_ptr as *mut FFIPieceMetadata,
                self.pieces_len,
                self.pieces_len,
            ));
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_get_seal_status_response(ptr: *mut GetSealStatusResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// FFIStagedSectorMetadata
///////////////////////////

#[repr(C)]
pub struct FFIStagedSectorMetadata {
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,

    // must be one of: Pending, Failed, Sealing
    pub seal_status_code: FFISealStatus,

    // if sealing failed - here's the error
    pub seal_error_msg: *const libc::c_char,
}

impl Drop for FFIStagedSectorMetadata {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.sector_access as *mut libc::c_char);
            free_c_str(self.seal_error_msg as *mut libc::c_char);
            drop(Vec::from_raw_parts(
                self.pieces_ptr as *mut FFIPieceMetadata,
                self.pieces_len,
                self.pieces_len,
            ));
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// FFISealedSectorMetadata
///////////////////////////

#[repr(C)]
pub struct FFISealedSectorMetadata {
    pub comm_d: [u8; 32],
    pub comm_r: [u8; 32],
    pub comm_r_star: [u8; 32],
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub snark_proof: [u8; API_POREP_PROOF_BYTES],
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,
}

impl Drop for FFISealedSectorMetadata {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.sector_access as *mut libc::c_char);
            drop(Vec::from_raw_parts(
                self.pieces_ptr as *mut FFIPieceMetadata,
                self.pieces_len,
                self.pieces_len,
            ));
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// GetSealedSectorsResponse
////////////////////////////

#[repr(C)]
pub struct GetSealedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub sectors_len: libc::size_t,
    pub sectors_ptr: *const FFISealedSectorMetadata,
}

impl Default for GetSealedSectorsResponse {
    fn default() -> GetSealedSectorsResponse {
        GetSealedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sectors_len: 0,
            sectors_ptr: ptr::null(),
        }
    }
}

impl Drop for GetSealedSectorsResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
            drop(Vec::from_raw_parts(
                self.sectors_ptr as *mut FFISealedSectorMetadata,
                self.sectors_len,
                self.sectors_len,
            ));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_get_sealed_sectors_response(ptr: *mut GetSealedSectorsResponse) {
    let _ = Box::from_raw(ptr);
}

///////////////////////////////////////////////////////////////////////////////
/// GetStagedSectorsResponse
////////////////////////////

#[repr(C)]
pub struct GetStagedSectorsResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,

    pub sectors_len: libc::size_t,
    pub sectors_ptr: *const FFIStagedSectorMetadata,
}

impl Default for GetStagedSectorsResponse {
    fn default() -> GetStagedSectorsResponse {
        GetStagedSectorsResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            sectors_len: 0,
            sectors_ptr: ptr::null(),
        }
    }
}

impl Drop for GetStagedSectorsResponse {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.error_msg as *mut libc::c_char);
            drop(Vec::from_raw_parts(
                self.sectors_ptr as *mut FFIStagedSectorMetadata,
                self.sectors_len,
                self.sectors_len,
            ));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_get_staged_sectors_response(ptr: *mut GetStagedSectorsResponse) {
    let _ = Box::from_raw(ptr);
}
