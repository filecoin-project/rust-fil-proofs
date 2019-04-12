use libc;
use slog::*;
use std::mem;
use std::ptr;
use std::slice::from_raw_parts;

use crate::api::post_adapter::*;
use crate::api::responses::err_code_and_msg;
use crate::api::responses::FCPResponseStatus;
use crate::api::responses::FFIPieceMetadata;
use crate::api::responses::FFISealStatus;
use crate::api::sector_builder::metadata::SealStatus;
use crate::api::sector_builder::SectorBuilder;
use crate::FCP_LOG;
use ffi_toolkit::rust_str_to_c_str;
use ffi_toolkit::{c_str_to_rust_str, raw_ptr};
use sector_base::api::bytes_amount::UnpaddedBytesAmount;
use sector_base::api::porep_config::PoRepConfig;
use sector_base::api::porep_config::PoRepProofPartitions;
use sector_base::api::post_config::PoStConfig;
use sector_base::api::post_config::PoStProofPartitions;
use sector_base::api::sector_class::SectorClass;
use sector_base::api::sector_size::SectorSize;

pub mod internal;
pub mod post_adapter;
pub mod responses;
mod sector_builder;

/// Note: These values need to be kept in sync with what's in api/internal.rs.
/// Due to limitations of cbindgen, we can't define a constant whose value is
/// a non-primitive (e.g. an expression like 192 * 2 or internal::STUFF) and
/// see the constant in the generated C-header file.
pub const API_POREP_PROOF_BYTES: usize = 384;
pub const API_POST_PROOF_BYTES: usize = 192;

/// Verifies the output of seal.
///
#[no_mangle]
pub unsafe extern "C" fn verify_seal(
    sector_size: FFISectorSize,
    comm_r: &[u8; 32],
    comm_d: &[u8; 32],
    comm_r_star: &[u8; 32],
    prover_id: &[u8; 31],
    sector_id: &[u8; 31],
    proof: &[u8; API_POREP_PROOF_BYTES],
) -> *mut responses::VerifySealResponse {
    info!(FCP_LOG, "verify_seal: {}", "start"; "target" => "FFI");

    let mut response: responses::VerifySealResponse = Default::default();

    let porep_config = match sector_size {
        FFISectorSize::SSB_OneKiB => PoRepConfig::Test,
        _ => PoRepConfig::Live(sector_size.into(), PoRepProofPartitions::Two),
    };

    match internal::verify_seal(
        porep_config,
        *comm_r,
        *comm_d,
        *comm_r_star,
        prover_id,
        sector_id,
        proof,
    ) {
        Ok(true) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.is_valid = true;
        }
        Ok(false) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.is_valid = false;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    info!(FCP_LOG, "verify_seal: {}", "finish"; "target" => "FFI");

    raw_ptr(response)
}

/// Generates a proof-of-spacetime for the given replica commitments.
///
#[no_mangle]
pub unsafe extern "C" fn generate_post(
    ptr: *mut SectorBuilder,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    challenge_seed: &[u8; 32],
) -> *mut responses::GeneratePoStResponse {
    info!(FCP_LOG, "generate_post: {}", "start"; "target" => "FFI");

    let comm_rs = from_raw_parts(flattened_comm_rs_ptr, flattened_comm_rs_len)
        .iter()
        .step_by(32)
        .fold(Default::default(), |mut acc: Vec<[u8; 32]>, item| {
            let sliced = from_raw_parts(item, 32);
            let mut x: [u8; 32] = Default::default();
            x.copy_from_slice(&sliced[..32]);
            acc.push(x);
            acc
        });

    let mut response: responses::GeneratePoStResponse = Default::default();

    match (*ptr).generate_post(&comm_rs, challenge_seed) {
        Ok(GeneratePoStDynamicSectorsCountOutput { proofs, faults }) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            let flattened_proofs: Vec<u8> = proofs.iter().flat_map(|x| x.iter().cloned()).collect();

            response.flattened_proofs_len = flattened_proofs.len();
            response.flattened_proofs_ptr = flattened_proofs.as_ptr();

            response.faults_len = faults.len();
            response.faults_ptr = faults.as_ptr();

            // we'll free this stuff when we free the GeneratePoSTResponse
            mem::forget(flattened_proofs);
            mem::forget(faults);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    info!(FCP_LOG, "generate_post: {}", "finish"; "target" => "FFI");

    raw_ptr(response)
}

/// Verifies that a proof-of-spacetime is valid.
///
#[no_mangle]
pub unsafe extern "C" fn verify_post(
    sector_size: FFISectorSize,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    challenge_seed: &[u8; 32],
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
    faults_ptr: *const u64,
    faults_len: libc::size_t,
) -> *mut responses::VerifyPoSTResponse {
    info!(FCP_LOG, "verify_post: {}", "start"; "target" => "FFI");

    let mut response: responses::VerifyPoSTResponse = Default::default();

    let post_config = match sector_size {
        FFISectorSize::SSB_OneKiB => PoStConfig::Test,
        _ => PoStConfig::Live(sector_size.into(), PoStProofPartitions::One),
    };

    let comm_rs = from_raw_parts(flattened_comm_rs_ptr, flattened_comm_rs_len)
        .iter()
        .step_by(32)
        .fold(Default::default(), |mut acc: Vec<[u8; 32]>, item| {
            let sliced = from_raw_parts(item, 32);
            let mut x: [u8; 32] = Default::default();
            x.copy_from_slice(&sliced[..32]);
            acc.push(x);
            acc
        });

    let proofs = from_raw_parts(flattened_proofs_ptr, flattened_proofs_len)
        .iter()
        .step_by(192)
        .fold(Default::default(), |mut acc: Vec<[u8; 192]>, item| {
            let sliced = from_raw_parts(item, 192);
            let mut x: [u8; 192] = [0; 192];
            x.copy_from_slice(&sliced[..192]);
            acc.push(x);
            acc
        });

    let faults = from_raw_parts(faults_ptr, faults_len);

    let safe_challenge_seed = {
        let mut cs = [0; 32];
        cs.copy_from_slice(challenge_seed);
        cs[31] &= 0b00111111;
        cs
    };

    match internal::verify_post(VerifyPoStDynamicSectorsCountInput {
        post_config,
        comm_rs,
        challenge_seed: safe_challenge_seed,
        proofs,
        faults: faults.to_vec(),
    }) {
        Ok(dynamic) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.is_valid = dynamic.is_valid;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    info!(FCP_LOG, "verify_post: {}", "finish"; "target" => "FFI");

    Box::into_raw(Box::new(response))
}

/// Initializes and returns a SectorBuilder.
///
#[no_mangle]
pub unsafe extern "C" fn init_sector_builder(
    sector_class: FFISectorClass,
    last_used_sector_id: u64,
    metadata_dir: *const libc::c_char,
    prover_id: &[u8; 31],
    sealed_sector_dir: *const libc::c_char,
    staged_sector_dir: *const libc::c_char,
    max_num_staged_sectors: u8,
) -> *mut responses::InitSectorBuilderResponse {
    let mut response: responses::InitSectorBuilderResponse = Default::default();

    match SectorBuilder::init_from_metadata(
        sector_class.into(),
        last_used_sector_id,
        c_str_to_rust_str(metadata_dir).to_string(),
        *prover_id,
        c_str_to_rust_str(sealed_sector_dir).to_string(),
        c_str_to_rust_str(staged_sector_dir).to_string(),
        max_num_staged_sectors,
    ) {
        Ok(sb) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.sector_builder = raw_ptr(sb);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// Destroys a SectorBuilder.
///
#[no_mangle]
pub unsafe extern "C" fn destroy_sector_builder(ptr: *mut SectorBuilder) {
    let _ = Box::from_raw(ptr);
}

/// Returns the number of user bytes that will fit into a staged sector.
///
#[no_mangle]
pub unsafe extern "C" fn get_max_user_bytes_per_staged_sector(sector_size: FFISectorSize) -> u64 {
    u64::from(UnpaddedBytesAmount::from(SectorSize::from(sector_size)))
}

/// Writes user piece-bytes to a staged sector and returns the id of the sector
/// to which the bytes were written.
///
#[no_mangle]
pub unsafe extern "C" fn add_piece(
    ptr: *mut SectorBuilder,
    piece_key: *const libc::c_char,
    piece_bytes_amount: u64,
    piece_path: *const libc::c_char,
) -> *mut responses::AddPieceResponse {
    let piece_key = c_str_to_rust_str(piece_key);
    let piece_path = c_str_to_rust_str(piece_path);

    let mut response: responses::AddPieceResponse = Default::default();

    match (*ptr).add_piece(
        String::from(piece_key),
        piece_bytes_amount,
        String::from(piece_path),
    ) {
        Ok(sector_id) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.sector_id = sector_id;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// Unseals and returns the bytes associated with the provided piece key.
///
#[no_mangle]
pub unsafe extern "C" fn read_piece_from_sealed_sector(
    ptr: *mut SectorBuilder,
    piece_key: *const libc::c_char,
) -> *mut responses::ReadPieceFromSealedSectorResponse {
    let mut response: responses::ReadPieceFromSealedSectorResponse = Default::default();

    let piece_key = c_str_to_rust_str(piece_key);

    match (*ptr).read_piece_from_sealed_sector(String::from(piece_key)) {
        Ok(piece_bytes) => {
            response.status_code = FCPResponseStatus::FCPNoError;
            response.data_ptr = piece_bytes.as_ptr();
            response.data_len = piece_bytes.len();
            mem::forget(piece_bytes);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// For demo purposes. Seals all staged sectors.
///
#[no_mangle]
pub unsafe extern "C" fn seal_all_staged_sectors(
    ptr: *mut SectorBuilder,
) -> *mut responses::SealAllStagedSectorsResponse {
    let mut response: responses::SealAllStagedSectorsResponse = Default::default();

    match (*ptr).seal_all_staged_sectors() {
        Ok(_) => {
            response.status_code = FCPResponseStatus::FCPNoError;
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

/// Returns sector sealing status for the provided sector id if it exists. If
/// we don't know about the provided sector id, produce an error.
///
#[no_mangle]
pub unsafe extern "C" fn get_seal_status(
    ptr: *mut SectorBuilder,
    sector_id: u64,
) -> *mut responses::GetSealStatusResponse {
    let mut response: responses::GetSealStatusResponse = Default::default();

    match (*ptr).get_seal_status(sector_id) {
        Ok(seal_status) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            match seal_status {
                SealStatus::Sealed(meta) => {
                    let meta = *meta;

                    response.seal_status_code = FFISealStatus::Sealed;
                    response.comm_d = meta.comm_d;
                    response.comm_r = meta.comm_r;
                    response.comm_r_star = meta.comm_r_star;
                    response.snark_proof = meta.snark_proof;
                    response.sector_id = meta.sector_id;
                    response.sector_access = rust_str_to_c_str(meta.sector_access);

                    let pieces = meta
                        .pieces
                        .iter()
                        .map(|p| FFIPieceMetadata {
                            piece_key: rust_str_to_c_str(p.piece_key.to_string()),
                            num_bytes: p.num_bytes.into(),
                        })
                        .collect::<Vec<FFIPieceMetadata>>();

                    response.pieces_ptr = pieces.as_ptr();
                    response.pieces_len = pieces.len();

                    mem::forget(pieces);
                }
                SealStatus::Sealing => {
                    response.seal_status_code = FFISealStatus::Sealing;
                }
                SealStatus::Pending => {
                    response.seal_status_code = FFISealStatus::Pending;
                }
                SealStatus::Failed(err) => {
                    response.seal_status_code = FFISealStatus::Failed;
                    response.seal_error_msg = rust_str_to_c_str(err);
                }
            }
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn get_sealed_sectors(
    ptr: *mut SectorBuilder,
) -> *mut responses::GetSealedSectorsResponse {
    let mut response: responses::GetSealedSectorsResponse = Default::default();

    match (*ptr).get_sealed_sectors() {
        Ok(sealed_sectors) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            let sectors = sealed_sectors
                .iter()
                .map(|meta| {
                    let pieces = meta
                        .pieces
                        .iter()
                        .map(|p| FFIPieceMetadata {
                            piece_key: rust_str_to_c_str(p.piece_key.to_string()),
                            num_bytes: p.num_bytes.into(),
                        })
                        .collect::<Vec<FFIPieceMetadata>>();

                    let sector = responses::FFISealedSectorMetadata {
                        comm_d: meta.comm_d,
                        comm_r: meta.comm_r,
                        comm_r_star: meta.comm_r_star,
                        sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                        sector_id: meta.sector_id,
                        snark_proof: meta.snark_proof,
                        pieces_len: pieces.len(),
                        pieces_ptr: pieces.as_ptr(),
                    };

                    mem::forget(pieces);

                    sector
                })
                .collect::<Vec<responses::FFISealedSectorMetadata>>();

            response.sectors_len = sectors.len();
            response.sectors_ptr = sectors.as_ptr();

            mem::forget(sectors);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[no_mangle]
pub unsafe extern "C" fn get_staged_sectors(
    ptr: *mut SectorBuilder,
) -> *mut responses::GetStagedSectorsResponse {
    let mut response: responses::GetStagedSectorsResponse = Default::default();

    match (*ptr).get_staged_sectors() {
        Ok(staged_sectors) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            let sectors = staged_sectors
                .iter()
                .map(|meta| {
                    let pieces = meta
                        .pieces
                        .iter()
                        .map(|p| FFIPieceMetadata {
                            piece_key: rust_str_to_c_str(p.piece_key.to_string()),
                            num_bytes: p.num_bytes.into(),
                        })
                        .collect::<Vec<FFIPieceMetadata>>();

                    let mut sector = responses::FFIStagedSectorMetadata {
                        sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                        sector_id: meta.sector_id,
                        pieces_len: pieces.len(),
                        pieces_ptr: pieces.as_ptr(),
                        seal_status_code: FFISealStatus::Pending,
                        seal_error_msg: ptr::null(),
                    };

                    match meta.seal_status {
                        SealStatus::Failed(ref s) => {
                            sector.seal_status_code = FFISealStatus::Failed;
                            sector.seal_error_msg = rust_str_to_c_str(s.clone());
                        }
                        SealStatus::Sealing => {
                            sector.seal_status_code = FFISealStatus::Sealing;
                        }
                        SealStatus::Pending => {
                            sector.seal_status_code = FFISealStatus::Pending;
                        }
                        SealStatus::Sealed(_) => {
                            sector.seal_status_code = FFISealStatus::Sealed;
                        }
                    };

                    mem::forget(pieces);

                    sector
                })
                .collect::<Vec<responses::FFIStagedSectorMetadata>>();

            response.sectors_len = sectors.len();
            response.sectors_ptr = sectors.as_ptr();

            mem::forget(sectors);
        }
        Err(err) => {
            let (code, ptr) = err_code_and_msg(&err);
            response.status_code = code;
            response.error_msg = ptr;
        }
    }

    raw_ptr(response)
}

#[repr(C)]
pub struct FFISectorClass {
    sector_size: FFISectorSize,
    seal_proof_partitions: FFISealProofPartitions,
    post_proof_partitions: FFIPoStProofPartitions,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum FFISectorSize {
    SSB_OneKiB,
    SSB_TwoHundredFiftySixMiB,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum FFISealProofPartitions {
    SPP_One,
    SPP_Two,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum FFIPoStProofPartitions {
    PPP_One,
}

impl From<FFISectorSize> for SectorSize {
    fn from(x: FFISectorSize) -> Self {
        match x {
            FFISectorSize::SSB_OneKiB => SectorSize::OneKiB,
            FFISectorSize::SSB_TwoHundredFiftySixMiB => SectorSize::TwoHundredFiftySixMiB,
        }
    }
}

impl From<FFISealProofPartitions> for PoRepProofPartitions {
    fn from(x: FFISealProofPartitions) -> Self {
        match x {
            FFISealProofPartitions::SPP_One => PoRepProofPartitions::One,
            FFISealProofPartitions::SPP_Two => PoRepProofPartitions::Two,
        }
    }
}

impl From<FFIPoStProofPartitions> for PoStProofPartitions {
    fn from(x: FFIPoStProofPartitions) -> Self {
        match x {
            FFIPoStProofPartitions::PPP_One => PoStProofPartitions::One,
        }
    }
}

impl From<FFISectorClass> for SectorClass {
    fn from(x: FFISectorClass) -> Self {
        SectorClass::Live(
            x.sector_size.into(),
            x.seal_proof_partitions.into(),
            x.post_proof_partitions.into(),
        )
    }
}
