use libc;
use std::ffi::{CStr, CString};
use std::mem::forget;
use std::path::PathBuf;
use std::slice;

use api_impl;

type Commitment = [u8; 32];
type StatusCode = u8;

// arrays cannot be passed by value in C; callers instead pass a pointer to the
// head and Rust makes runtime assertions of length while marshaling
type ProverIDPtr = *const u8;
type ChallengeSeedPtr = *const u8;
type RandomSeedPtr = *const u8;
type SealResultPtr = *const u8;
type CommitmentPtr = *const u8;
type UnsealResultPtr = *mut u64;
type SectorAccess = *const libc::c_char;

fn from_cstr(c_str: *const libc::c_char) -> String {
    unsafe {
        CStr::from_ptr(c_str)
            .to_string_lossy()
            .to_owned()
            .to_string()
    }
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
    unsealed_path: SectorAccess,
    sealed_path: SectorAccess,
    _prover_id_ptr: ProverIDPtr,
    _challenge_seed_ptr: ChallengeSeedPtr,
    _random_seed_ptr: RandomSeedPtr,
    result_ptr: SealResultPtr,
) -> StatusCode {
    let unsealed_path_buf = PathBuf::from(from_cstr(unsealed_path));
    let sealed_path_buf = PathBuf::from(from_cstr(sealed_path));

    let _copied = api_impl::seal(&unsealed_path_buf, &sealed_path_buf);

    let result: Result<[Commitment; 2], String> = Ok([DUMMY_COMM_R, DUMMY_COMM_D]);

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

    if comm_r == DUMMY_COMM_R && comm_d == DUMMY_COMM_D {
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
        30 => CString::new("failed to unseal"),
        _ => CString::new("unknown status code"),
    }.unwrap();

    let p = s.as_ptr();

    forget(s);

    p
}

/// Unseals bytes from a sealed sector-file and writes them to the output path and returns a status
/// code indicating success or failure.
///
/// It is possible that the unseal operation writes a number of bytes to the output_path which is
/// less than num_bytes.
///
/// # Arguments
///
/// * `sealed_path`   - path of sealed sector-file
/// * `output_path`  - path where unsealed sector file's bytes should be written
/// * `start_offset` - zero-based byte offset in original, unsealed sector-file
/// * `num_bytes`    - number of bytes to unseal (corresponds to contents of unsealed sector-file)
/// * `result_ptr`   - pointer to a u64, mutated by unseal in order to communicate the number of
///                    bytes that were unsealed and written to the output_path
/// ```
#[no_mangle]
pub extern "C" fn unseal(
    sealed_path: SectorAccess,
    output_path: SectorAccess,
    start_offset: u64,
    num_bytes: u64,
    result_ptr: UnsealResultPtr,
) -> StatusCode {
    let sealed_path_buf = PathBuf::from(from_cstr(sealed_path));
    let output_path_buf = PathBuf::from(from_cstr(output_path));

    match api_impl::unseal(&sealed_path_buf, &output_path_buf, start_offset, num_bytes) {
        Ok(num_unsealed_bytes) => {
            unsafe { result_ptr.write(num_unsealed_bytes) };
            0
        }
        Err(_) => 30,
    }
}

#[no_mangle]
pub extern "C" fn generatePost() {
    unimplemented!()
}

#[no_mangle]
pub extern "C" fn verifyPost() {
    unimplemented!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs::{read_to_string, write};
    use std::str::from_utf8_unchecked;
    use tempfile;

    fn path_to_c_str(p: &PathBuf) -> *const libc::c_char {
        let s = p.to_str().unwrap();
        CString::new(s).unwrap().into_raw()
    }

    #[test]
    fn seal_verify() {
        let dir = tempfile::tempdir().unwrap();
        let seal_input_path = dir.path().join("unsealed");
        let seal_output_path = dir.path().join("unsealed");

        let result: [u8; 64] = [0; 64];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];

        let good_seal = seal(
            path_to_c_str(&seal_input_path),
            path_to_c_str(&seal_output_path),
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
    fn seal_unseal_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let seal_input_path = dir.path().join("unsealed00");
        let seal_output_path = dir.path().join("sealed");
        let unseal_output_path = dir.path().join("unsealed01");

        let result: [u8; 64] = [0; 64];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];
        let result_ptr: &mut u64 = &mut 0;

        let contents = b"hello, moto";
        let length = contents.len();

        match write(&seal_input_path, contents) {
            Ok(_) => (),
            Err(err) => panic!(err),
        }

        let good_seal = seal(
            path_to_c_str(&seal_input_path),
            path_to_c_str(&seal_output_path),
            &prover_id[0],
            &challenge_seed[0],
            &random_seed[0],
            &result[0],
        );

        assert_eq!(0, good_seal);

        let good_unseal = unseal(
            path_to_c_str(&seal_output_path),
            path_to_c_str(&unseal_output_path),
            0,
            length as u64,
            result_ptr,
        );

        assert_eq!(0, good_unseal);
        assert_eq!(length as u64, *result_ptr);

        let buffer = match read_to_string(unseal_output_path) {
            Ok(s) => s,
            Err(err) => panic!(err),
        };

        assert_eq!(unsafe { from_utf8_unchecked(contents) }, buffer);
    }
}
