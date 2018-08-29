use libc;
use std::ffi::{CStr, CString};
use std::mem::forget;
use std::path::PathBuf;
use std::slice;

mod internal;

type StatusCode = u8;

// arrays cannot be passed by value in C; callers instead pass a pointer to the
// head and Rust makes runtime assertions of length while marshaling
type ProverIDPtr = *const u8;
type ChallengeSeedPtr = *const u8;
type RandomSeedPtr = *const u8;
type SealResultPtr = *const u8;
type CommitmentPtr = *const u8;
type SnarkProofPtr = *const u8;
type GetUnsealedRangeResultPtr = *mut u64;
type SectorAccess = *const libc::c_char;

/// These are also defined in api::internal, but we make them explicit here for API consumers.
/// How big, in bytes, is a SNARK proof?
pub const SNARK_BYTES: usize = 192;
pub const SECTOR_BYTES: u64 = 64;

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

fn u8ptr_to_vector(x: *const u8, length: usize) -> Vec<u8> {
    let s = unsafe { slice::from_raw_parts(x, SNARK_BYTES).to_owned() };

    assert_eq!(
        s.len(),
        length,
        "actual len(s) = {}, expected len(s) = {}",
        s.len(),
        length
    );

    let mut out = vec![0; length];
    out.copy_from_slice(&s[0..length]);
    out
}

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
    prover_id_ptr: ProverIDPtr,
    challenge_seed_ptr: ChallengeSeedPtr,
    _random_seed_ptr: RandomSeedPtr,
    result_ptr: SealResultPtr,
) -> StatusCode {
    let unsealed_path_buf = PathBuf::from(from_cstr(unsealed_path));
    let sealed_path_buf = PathBuf::from(from_cstr(sealed_path));
    let prover_id = u8ptr_to_array31(prover_id_ptr);
    let challenge_seed = u8ptr_to_array32(challenge_seed_ptr);

    let result = internal::seal(
        &unsealed_path_buf,
        &sealed_path_buf,
        prover_id,
        challenge_seed,
    );

    match result {
        Ok((comm_r, comm_d, snark_proof)) => {
            // let caller manage this memory, preventing the need for calling back into
            // Rust code later to deallocate
            unsafe {
                for x in 0..32 {
                    *(result_ptr.offset(x as isize) as *mut u8) = comm_r[x];
                    *(result_ptr.offset((x + 32) as isize) as *mut u8) = comm_d[x];
                }
                for (i, elt) in snark_proof.iter().enumerate() {
                    *(result_ptr.offset((i + 64) as isize) as *mut u8) = *elt;
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
/// * `comm_r_ptr`   - pointer to first cell in a 32-length array of u8 contaning the replica
///                    commitment
/// * `comm_d_ptr`   - pointer to first cell in a 32-length array of u8 containing the data commitment
/// * `prover_id_ptr`- pointer to first cell in a 31-length array of u8
/// * `proof_ptr`    - pointer to first cell in a SNARK_BYTES-length array of u8
/// ```
#[no_mangle]
pub extern "C" fn verify_seal(
    comm_r_ptr: CommitmentPtr,
    comm_d_ptr: CommitmentPtr,
    prover_id_ptr: ProverIDPtr,
    challenge_seed_ptr: ChallengeSeedPtr,
    proof_ptr: SnarkProofPtr,
) -> StatusCode {
    let comm_r = u8ptr_to_array32(comm_r_ptr);
    let comm_d = u8ptr_to_array32(comm_d_ptr);
    let prover_id = u8ptr_to_array31(prover_id_ptr);
    let challenge_seed = u8ptr_to_array32(challenge_seed_ptr);
    let proof = u8ptr_to_vector(proof_ptr, SNARK_BYTES);

    match internal::verify_seal(comm_r, comm_d, prover_id, challenge_seed, &proof) {
        Ok(true) => 0,
        Ok(false) => 20,
        Err(_) => 21,
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
        21 => CString::new("unhandled verify_seal error"),
        30 => CString::new("failed to get unsealed range"),
        _ => CString::new("unknown status code"),
    }.unwrap();

    let p = s.as_ptr();

    forget(s);

    p
}

/// Gets bytes from a sealed sector-file and writes them, unsealed, to the output path and returns a
/// status code indicating success or failure.
///
/// It is possible that the get_unsealed_range operation writes a number of bytes to the output_path which is
/// less than num_bytes.
///
/// # Arguments
///
/// * `sealed_path`  - path of sealed sector-file
/// * `output_path`  - path where sector file's unsealed bytes should be written
/// * `start_offset` - zero-based byte offset in original, unsealed sector-file
/// * `num_bytes`    - number of bytes to unseal and get (corresponds to contents of unsealed sector-file)
/// * `prover_id_ptr`- pointer to first cell in a 31-length array of u8
/// * `result_ptr`   - pointer to a u64, mutated by get_unsealed_range in order to communicate the number of
///                    bytes that were unsealed and written to the output_path
/// ```
#[no_mangle]
pub extern "C" fn get_unsealed_range(
    sealed_path: SectorAccess,
    output_path: SectorAccess,
    start_offset: u64,
    num_bytes: u64,
    prover_id_ptr: ProverIDPtr,
    result_ptr: GetUnsealedRangeResultPtr,
) -> StatusCode {
    let sealed_path_buf = PathBuf::from(from_cstr(sealed_path));
    let output_path_buf = PathBuf::from(from_cstr(output_path));
    let prover_id = u8ptr_to_array31(prover_id_ptr);

    match internal::get_unsealed_range(
        &sealed_path_buf,
        &output_path_buf,
        prover_id,
        start_offset,
        num_bytes,
    ) {
        Ok(num_bytes) => {
            unsafe { result_ptr.write(num_bytes) };
            0
        }
        Err(_) => 30,
    }
}

/// Gets an entire sealed sector-file and writes it, unsealed, to the output path and returns a
/// status code indicating success or failure.
///
/// # Arguments
///
/// * `sealed_path`  - path of sealed sector-file
/// * `output_path`  - path where sector file's unsealed bytes should be written
/// * `prover_id_ptr`- pointer to first cell in a 31-length array of u8
/// ```
#[no_mangle]
pub extern "C" fn get_unsealed(
    sealed_path: SectorAccess,
    output_path: SectorAccess,
    prover_id_ptr: ProverIDPtr,
) -> StatusCode {
    let sealed_path_buf = PathBuf::from(from_cstr(sealed_path));
    let output_path_buf = PathBuf::from(from_cstr(output_path));
    let prover_id = u8ptr_to_array31(prover_id_ptr);

    match internal::get_unsealed_range(
        &sealed_path_buf,
        &output_path_buf,
        prover_id,
        0,
        SECTOR_BYTES,
    ) {
        Ok(num_bytes) => if num_bytes == SECTOR_BYTES {
            0
        } else {
            30
        },
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
    use std::fs::write;
    use std::fs::File;
    use std::io::Read;
    use tempfile::{self, TempDir};

    fn path_to_c_str(p: &PathBuf) -> *const libc::c_char {
        let s = p.to_str().unwrap();
        CString::new(s).unwrap().into_raw()
    }

    fn create_tmp_file(dir: &TempDir, name: &str) -> PathBuf {
        let path = dir.path().join(name);
        File::create(&path).unwrap();
        path
    }

    #[test]
    fn seal_verify() {
        let dir = tempfile::tempdir().unwrap();
        let seal_input_path = create_tmp_file(&dir, "unsealed");
        let seal_output_path = create_tmp_file(&dir, "sealed");

        let result: [u8; 256] = [0; 256];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];

        let contents = b"hello, moto";

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

        let good_verify = verify_seal(
            &result[0],
            &result[32],
            &prover_id[0],
            &challenge_seed[0],
            &result[64],
        );
        let bad_verify = verify_seal(
            &result[32],
            &result[0],
            &prover_id[0],
            &challenge_seed[0],
            &result[64],
        );

        assert_eq!(0, good_seal);
        assert_eq!(0, good_verify);
        assert_eq!(20, bad_verify);
    }

    #[test]
    fn seal_unsealed_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let seal_output_path = create_tmp_file(&dir, "seal_out");
        let get_unsealed_range_output_path = create_tmp_file(&dir, "get_unsealed_range_out");
        let seal_input_path = create_tmp_file(&dir, "seal_in");

        let result: [u8; 256] = [0; 256];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];

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

        let good_unsealed = get_unsealed(
            path_to_c_str(&seal_output_path),
            path_to_c_str(&get_unsealed_range_output_path),
            &prover_id[0],
        );

        assert_eq!(0, good_unsealed);

        let mut file = File::open(get_unsealed_range_output_path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        assert_eq!(contents[..], buf[0..length]);
    }

    #[test]
    fn seal_unsealed_range_roundtrip() {
        let result_ptr = &mut 0u64;
        let dir = tempfile::tempdir().unwrap();
        let seal_output_path = create_tmp_file(&dir, "seal_out");
        let get_unsealed_range_output_path = create_tmp_file(&dir, "get_unsealed_range_out");
        let seal_input_path = create_tmp_file(&dir, "seal_in");

        let result: [u8; 256] = [0; 256];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];

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

        let offset = 5;
        let range_length = length as u64 - offset;
        let good_unsealed = get_unsealed_range(
            path_to_c_str(&seal_output_path),
            path_to_c_str(&get_unsealed_range_output_path),
            offset,
            range_length,
            &prover_id[0],
            result_ptr,
        );

        assert_eq!(0, good_unsealed);
        assert_eq!(range_length, *result_ptr);

        let mut file = File::open(get_unsealed_range_output_path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        assert_eq!(
            contents[(offset as usize)..],
            buf[0..(range_length as usize)]
        );
    }
}
