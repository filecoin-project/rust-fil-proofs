use libc;
use std::ffi::{CStr, CString};
use std::mem::forget;
use std::path::PathBuf;
use std::slice;

use api_impl;

type Commitment = [u8; 32];
type ProverID = [u8; 31];
type ChallengeSeed = [u8; 32];
type RandomSeed = [u8; 32];
type StatusCode = u8;

// arrays cannot be passed by value in C; callers instead pass a pointer to the
// head and Rust makes runtime assertions of length while marshaling
type ProverIDPtr = *const u8;
type ChallengeSeedPtr = *const u8;
type RandomSeedPtr = *const u8;
type ResultPtr = *const u8;
type CommitmentPtr = *const u8;
type SectorAccessPtr = *const libc::c_char;

fn from_cstr(c_str: *const libc::c_char) -> String {
    unsafe {
        CStr::from_ptr(c_str)
            .to_string_lossy()
            .to_owned()
            .to_string()
    }
}

fn u8ptr_to_array31(x: *const u8) -> [u8; 31] {
    let s = unsafe { slice::from_raw_parts(x, 31).to_owned() };

    assert_eq!(
        s.len(),
        31,
        "actual len(s) = {}, expected len(s) = {}",
        s.len(),
        31
    );

    let mut out: [u8; 31] = Default::default();
    out.copy_from_slice(&s[0..31]);
    out
}

fn u8ptr_to_array32(x: *const u8) -> [u8; 32] {
    let s = unsafe { slice::from_raw_parts(x, 32).to_owned() };

    assert_eq!(
        s.len(),
        32,
        "actual len(s) = {}, expected len(s) = {}",
        s.len(),
        32
    );

    let mut out: [u8; 32] = Default::default();
    out.copy_from_slice(&s[0..32]);
    out
}

const DUMMY_COMM_R: Commitment = *b"12345678901234567890123456789012";
const DUMMY_COMM_D: Commitment = *b"09876543210987654321098765432109";

/// Seals a sector and returns a status code indicating success or failure.
///
/// # Arguments
///
/// * `unsealed`            - path of unsealed sector-file
/// * `sealed`              - path of sealed sector-file
/// * `prover_id_ptr`       - pointer to first cell in a 31-length array of u8
/// * `challenge_seed_ptr`  - pointer to first cell in a 32-length array of u8
/// * `random_seed_ptr`     - pointer to first cell in a 32-length array of u8
/// * `result_ptr`          - pointer to first cell in a 64-length array of u8,
///                           mutated by seal in order to pass commitments back
///                           to caller (first 32 elements correspond to comm_r
///                           and second 32 to comm_d)
/// ```
#[no_mangle]
pub extern "C" fn seal(
    unsealed: SectorAccessPtr,
    sealed: SectorAccessPtr,
    prover_id_ptr: ProverIDPtr,
    challenge_seed_ptr: ChallengeSeedPtr,
    random_seed_ptr: RandomSeedPtr,
    result_ptr: ResultPtr,
) -> StatusCode {
    let prover_id = u8ptr_to_array31(prover_id_ptr);
    let challenge_seed = u8ptr_to_array32(challenge_seed_ptr);
    let random_seed = u8ptr_to_array32(random_seed_ptr);

    let result = seal_internal(unsealed, sealed, prover_id, challenge_seed, random_seed);

    match result {
        Ok(comms) => {
            // let caller manage this memory, preventing the need for calling back into
            // Rust code later to deallocate
            unsafe {
                for x in 0..32 {
                    *(result_ptr.offset(x as isize) as *mut u8) = comms[0][x];
                    *(result_ptr.offset((x + 32) as isize) as *mut u8) = comms[1][x];
                }
            };

            0
        }
        Err(_) => {
            // TODO: make a decision about which status code to return using Err
            10
        }
    }
}

/// Verifies the output of seal and returns a status code indicating success or failure.
///
/// # Arguments
///
/// * `comm_r_ptr` - pointer to first cell in a 32-length array of u8 contaning the replica
///                  commitment
/// * `comm_d_ptr` - pointer to first cell in a 32-length array of u8 containing the data commitment
/// ```
#[no_mangle]
pub extern "C" fn verify_seal(comm_r_ptr: CommitmentPtr, comm_d_ptr: CommitmentPtr) -> StatusCode {
    let comm_r = u8ptr_to_array32(comm_r_ptr);
    let comm_d = u8ptr_to_array32(comm_d_ptr);

    if verify_seal_internal(comm_r, comm_d) {
        0
    } else {
        20
    }
}

/// Returns a human-readible message for the provided status code.
///
/// Callers are responsible for freeing the returned string.
///
/// # Arguments
///
/// * `status_code` - a status code returned from an FPS operation, such as seal or verify_seal
/// ```
#[no_mangle]
pub extern "C" fn status_to_string(status_code: u8) -> *const libc::c_char {
    let s = match status_code {
        0 => CString::new("success"),
        10 => CString::new("failed to seal"),
        20 => CString::new("invalid replica and/or data commitment"),
        _ => CString::new("unknown status code"),
    }.unwrap();

    let p = s.as_ptr();

    forget(s);

    p
}

#[no_mangle]
pub extern "C" fn unseal() {
    unimplemented!()
}

#[no_mangle]
pub extern "C" fn generatePost() {
    unimplemented!()
}

#[no_mangle]
pub extern "C" fn verifyPost() {
    unimplemented!()
}

fn seal_internal(
    unsealed: SectorAccessPtr,
    sealed: SectorAccessPtr,
    _prover_id: ProverID,
    _challenge_seed: ChallengeSeed,
    _random_seed: RandomSeed,
) -> Result<[Commitment; 2], String> {
    let in_path = PathBuf::from(from_cstr(unsealed));
    let out_path = PathBuf::from(from_cstr(sealed));

    let _copied = api_impl::seal(&in_path, &out_path);

    Ok([DUMMY_COMM_R, DUMMY_COMM_D])
}

fn verify_seal_internal(comm_r: Commitment, comm_d: Commitment) -> bool {
    comm_r == DUMMY_COMM_R && comm_d == DUMMY_COMM_D
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn as_raw_ptr(s: &str) -> *const libc::c_char {
        CString::new(s).unwrap().as_ptr()
    }

    #[test]
    fn seal_verify() {
        let result: [u8; 64] = [0; 64];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];

        let good_seal = seal(
            as_raw_ptr("sector123"),
            as_raw_ptr("sector123"),
            &prover_id[0],
            &challenge_seed[0],
            &random_seed[0],
            &result[0],
        );

        let good_verify = verify_seal(&result[0], &result[32]);
        let bad_verify = verify_seal(&result[32], &result[0]);

        assert_eq!(0, good_seal);
        assert_eq!(0, good_verify);
        assert_eq!(20, bad_verify);
    }

    #[test]
    fn seal_internal_verify() {
        let comms = seal_internal(
            as_raw_ptr("sector123"),
            as_raw_ptr("sector123"),
            [1; 31],
            [2; 32],
            [3; 32],
        );

        match comms {
            Ok(comms) => {
                assert_ne!(comms[0], comms[1]);
                assert!(verify_seal_internal(comms[0], comms[1]));
                assert!(!verify_seal_internal(comms[1], comms[0]));
            }
            Err(_) => panic!("seal_internal failed unexpectedly"),
        }
    }
}
