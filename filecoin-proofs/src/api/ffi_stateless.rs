use std::slice::from_raw_parts;

use libc;
use slog::*;

use ffi_toolkit::raw_ptr;
use sector_base::api::bytes_amount::UnpaddedBytesAmount;
use sector_base::api::porep_config::PoRepConfig;
use sector_base::api::porep_proof_partitions;
use sector_base::api::porep_proof_partitions::PoRepProofPartitions;
use sector_base::api::post_config::PoStConfig;
use sector_base::api::post_proof_partitions::PoStProofPartitions;
use sector_base::api::sector_class::SectorClass;
use sector_base::api::sector_size::SectorSize;
use sector_base::api::SINGLE_PARTITION_PROOF_LEN;

use crate::api::internal;
use crate::api::responses;
use crate::api::responses::err_code_and_msg;
use crate::api::responses::FCPResponseStatus;
use crate::FCP_LOG;

/// Verifies the output of seal.
///
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

/// Verifies that a proof-of-spacetime is valid.
///
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

        internal::verify_post(
            cfg,
            into_commitments(flattened_comm_rs_ptr, flattened_comm_rs_len),
            into_safe_challenge_seed(challenge_seed),
            bs,
            from_raw_parts(faults_ptr, faults_len).to_vec(),
        )
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

/// Returns the number of user bytes that will fit into a staged sector.
///
#[no_mangle]
pub unsafe extern "C" fn get_max_user_bytes_per_staged_sector(sector_size: u64) -> u64 {
    u64::from(UnpaddedBytesAmount::from(SectorSize(sector_size)))
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
    cs[31] &= 0b0011_1111;
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
