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
use sector_base::api::porep_proof_partitions;
use sector_base::api::porep_proof_partitions::PoRepProofPartitions;
use sector_base::api::post_config::PoStConfig;
use sector_base::api::post_proof_partitions::PoStProofPartitions;
use sector_base::api::sector_class::SectorClass;
use sector_base::api::sector_size::SectorSize;
use sector_base::api::SINGLE_PARTITION_PROOF_LEN;

pub mod internal;
pub mod post_adapter;
pub mod responses;
mod sector_builder;

/// Verifies the output of seal.
///
#[allow(dead_code)]
#[no_mangle]
pub unsafe extern "C" fn verify_seal(
    sector_size: u64,
    comm_r: &[u8; 32],
    comm_d: &[u8; 32],
    comm_r_star: &[u8; 32],
    prover_id: &[u8; 31],
    sector_id: &[u8; 31],
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> *mut responses::VerifySealResponse {
    info!(FCP_LOG, "verify_seal: {}", "start"; "target" => "FFI");

    let porep_bytes = try_into_porep_proof_bytes(proof_ptr, proof_len);

    let result = porep_bytes.and_then(|bs| {
        porep_proof_partitions::try_from_bytes(&bs).and_then(|ppp| {
            let cfg = PoRepConfig(SectorSize(sector_size), ppp);

            internal::verify_seal(
                cfg,
                *comm_r,
                *comm_d,
                *comm_r_star,
                prover_id,
                sector_id,
                &bs,
            )
        })
    });

    let mut response = responses::VerifySealResponse::default();

    match result {
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
    };

    info!(FCP_LOG, "verify_seal: {}", "finish"; "target" => "FFI");

    raw_ptr(response)
}

/// Generates a proof-of-spacetime for the given replica commitments.
///
#[allow(dead_code)]
#[no_mangle]
pub unsafe extern "C" fn generate_post(
    ptr: *mut SectorBuilder,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    challenge_seed: &[u8; 32],
) -> *mut responses::GeneratePoStResponse {
    info!(FCP_LOG, "generate_post: {}", "start"; "target" => "FFI");

    let comm_rs = into_commitments(flattened_comm_rs_ptr, flattened_comm_rs_len);

    let result = (*ptr).generate_post(&comm_rs, challenge_seed);

    let mut response = responses::GeneratePoStResponse::default();

    match result {
        Ok(GeneratePoStDynamicSectorsCountOutput { proofs, faults }) => {
            response.status_code = FCPResponseStatus::FCPNoError;

            let flattened_proofs: Vec<u8> = proofs.iter().flat_map(|x| x.iter().cloned()).collect();
            response.flattened_proofs_len = flattened_proofs.len();
            response.flattened_proofs_ptr = flattened_proofs.as_ptr();

            let class = (*ptr).get_sector_class();
            let PoStProofPartitions(n) = PoStProofPartitions::from(PoStConfig::from(class));
            response.proof_partitions = n;

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
#[allow(dead_code)]
#[no_mangle]
pub unsafe extern "C" fn verify_post(
    sector_size: u64,
    proof_partitions: u8,
    flattened_comm_rs_ptr: *const u8,
    flattened_comm_rs_len: libc::size_t,
    challenge_seed: &[u8; 32],
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
    faults_ptr: *const u64,
    faults_len: libc::size_t,
) -> *mut responses::VerifyPoSTResponse {
    info!(FCP_LOG, "verify_post: {}", "start"; "target" => "FFI");

    let post_bytes =
        try_into_post_proofs_bytes(proof_partitions, flattened_proofs_ptr, flattened_proofs_len);

    let result = post_bytes.and_then(|bs| {
        let cfg = PoStConfig(
            SectorSize(sector_size),
            PoStProofPartitions(proof_partitions),
        );

        internal::verify_post(VerifyPoStDynamicSectorsCountInput {
            post_config: cfg,
            comm_rs: into_commitments(flattened_comm_rs_ptr, flattened_comm_rs_len),
            challenge_seed: into_safe_challenge_seed(challenge_seed),
            proofs: bs,
            faults: from_raw_parts(faults_ptr, faults_len).to_vec(),
        })
    });

    let mut response = responses::VerifyPoSTResponse::default();

    match result {
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

    raw_ptr(response)
}

/// Initializes and returns a SectorBuilder.
///
#[allow(dead_code)]
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
    let result = SectorBuilder::init_from_metadata(
        from_ffi_sector_class(sector_class),
        last_used_sector_id,
        c_str_to_rust_str(metadata_dir).to_string(),
        *prover_id,
        c_str_to_rust_str(sealed_sector_dir).to_string(),
        c_str_to_rust_str(staged_sector_dir).to_string(),
        max_num_staged_sectors,
    );

    let mut response = responses::InitSectorBuilderResponse::default();

    match result {
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
#[allow(dead_code)]
#[no_mangle]
pub unsafe extern "C" fn destroy_sector_builder(ptr: *mut SectorBuilder) {
    let _ = Box::from_raw(ptr);
}

/// Returns the number of user bytes that will fit into a staged sector.
///
#[allow(dead_code)]
#[no_mangle]
pub unsafe extern "C" fn get_max_user_bytes_per_staged_sector(sector_size: u64) -> u64 {
    u64::from(UnpaddedBytesAmount::from(SectorSize(sector_size)))
}

/// Writes user piece-bytes to a staged sector and returns the id of the sector
/// to which the bytes were written.
///
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

                    let pieces = meta
                        .pieces
                        .iter()
                        .map(|p| FFIPieceMetadata {
                            piece_key: rust_str_to_c_str(p.piece_key.to_string()),
                            num_bytes: p.num_bytes.into(),
                        })
                        .collect::<Vec<FFIPieceMetadata>>();

                    response.comm_d = meta.comm_d;
                    response.comm_r = meta.comm_r;
                    response.comm_r_star = meta.comm_r_star;
                    response.pieces_len = pieces.len();
                    response.pieces_ptr = pieces.as_ptr();
                    response.proof_len = meta.proof.len();
                    response.proof_ptr = meta.proof.as_ptr();
                    response.seal_status_code = FFISealStatus::Sealed;
                    response.sector_access = rust_str_to_c_str(meta.sector_access);
                    response.sector_id = meta.sector_id;

                    mem::forget(meta.proof);
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

#[allow(dead_code)]
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

                    let snark_proof = meta.proof.clone();

                    let sector = responses::FFISealedSectorMetadata {
                        comm_d: meta.comm_d,
                        comm_r: meta.comm_r,
                        comm_r_star: meta.comm_r_star,
                        pieces_len: pieces.len(),
                        pieces_ptr: pieces.as_ptr(),
                        proofs_len: snark_proof.len(),
                        proofs_ptr: snark_proof.as_ptr(),
                        sector_access: rust_str_to_c_str(meta.sector_access.clone()),
                        sector_id: meta.sector_id,
                    };

                    mem::forget(snark_proof);
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

#[allow(dead_code)]
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

unsafe fn try_into_post_proofs_bytes(
    proof_partitions: u8,
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
) -> crate::error::Result<Vec<Vec<u8>>> {
    let chunk_size = proof_partitions as usize * SINGLE_PARTITION_PROOF_LEN;

    ensure!(
        flattened_proofs_len % chunk_size == 0,
        "proofs array len={:?} incompatible with partitions={:?}",
        flattened_proofs_len,
        proof_partitions
    );

    Ok(into_proof_vecs(
        chunk_size,
        flattened_proofs_ptr,
        flattened_proofs_len,
    ))
}

unsafe fn try_into_porep_proof_bytes(
    proof_ptr: *const u8,
    proof_len: libc::size_t,
) -> crate::error::Result<Vec<u8>> {
    into_proof_vecs(proof_len, proof_ptr, proof_len)
        .first()
        .map(Vec::clone)
        .ok_or_else(|| format_err!("no proofs in chunked vec"))
}

unsafe fn into_proof_vecs(
    proof_chunk: usize,
    flattened_proofs_ptr: *const u8,
    flattened_proofs_len: libc::size_t,
) -> Vec<Vec<u8>> {
    from_raw_parts(flattened_proofs_ptr, flattened_proofs_len)
        .iter()
        .step_by(proof_chunk)
        .fold(Default::default(), |mut acc: Vec<Vec<u8>>, item| {
            let sliced = from_raw_parts(item, proof_chunk);
            acc.push(sliced.to_vec());
            acc
        })
}

fn into_safe_challenge_seed(challenge_seed: &[u8; 32]) -> [u8; 32] {
    let mut cs = [0; 32];
    cs.copy_from_slice(challenge_seed);
    cs[31] &= 0b00111111;
    cs
}

unsafe fn into_commitments(
    flattened_comms_ptr: *const u8,
    flattened_comms_len: libc::size_t,
) -> Vec<[u8; 32]> {
    from_raw_parts(flattened_comms_ptr, flattened_comms_len)
        .iter()
        .step_by(32)
        .fold(Default::default(), |mut acc: Vec<[u8; 32]>, item| {
            let sliced = from_raw_parts(item, 32);
            let mut x: [u8; 32] = Default::default();
            x.copy_from_slice(&sliced[..32]);
            acc.push(x);
            acc
        })
}

#[repr(C)]
pub struct FFISectorClass {
    sector_size: u64,
    porep_proof_partitions: u8,
    post_proof_partitions: u8,
}

pub fn from_ffi_sector_class(fsc: FFISectorClass) -> SectorClass {
    match fsc {
        FFISectorClass {
            sector_size,
            porep_proof_partitions,
            post_proof_partitions,
        } => SectorClass(
            SectorSize(sector_size),
            PoRepProofPartitions(porep_proof_partitions),
            PoStProofPartitions(post_proof_partitions),
        ),
    }
}
