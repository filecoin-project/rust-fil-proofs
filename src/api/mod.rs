pub mod sss;
pub mod util;

use libc;
use std::ffi::CString;
use std::mem::forget;

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
pub unsafe extern "C" fn seal(
    unsealed_path: SectorAccess,
    sealed_path: SectorAccess,
    prover_id_ptr: ProverIDPtr,
    challenge_seed_ptr: ChallengeSeedPtr,
    _random_seed_ptr: RandomSeedPtr,
    result_ptr: SealResultPtr,
) -> StatusCode {
    let unsealed_path_buf = util::pbuf_from_c(unsealed_path);
    let sealed_path_buf = util::pbuf_from_c(sealed_path);
    let prover_id = util::u8ptr_to_array31(prover_id_ptr);
    let challenge_seed = util::u8ptr_to_array32(challenge_seed_ptr);

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
            for x in 0..32 {
                *(result_ptr.offset(x as isize) as *mut u8) = comm_r[x];
                *(result_ptr.offset((x + 32) as isize) as *mut u8) = comm_d[x];
            }

            for (i, elt) in snark_proof.iter().enumerate() {
                *(result_ptr.offset((i + 64) as isize) as *mut u8) = *elt;
            }

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
/// * `comm_r_ptr`         - pointer to first cell in a 32-length array of u8 contaning the replica
///                          commitment
/// * `comm_d_ptr`         - pointer to first cell in a 32-length array of u8 containing the data
///                          commitment
/// * `prover_id_ptr`      - pointer to first cell in a 31-length array of u8
/// * `challenge_seed_ptr` - pointer to first cell in a 32-length array of u8
/// * `proof_ptr`          - pointer to first cell in a SNARK_BYTES-length array of u8
/// ```
#[no_mangle]
pub unsafe extern "C" fn verify_seal(
    comm_r_ptr: CommitmentPtr,
    comm_d_ptr: CommitmentPtr,
    prover_id_ptr: ProverIDPtr,
    challenge_seed_ptr: ChallengeSeedPtr,
    proof_ptr: SnarkProofPtr,
) -> StatusCode {
    let comm_r = util::u8ptr_to_array32(comm_r_ptr);
    let comm_d = util::u8ptr_to_array32(comm_d_ptr);
    let prover_id = util::u8ptr_to_array31(prover_id_ptr);
    let challenge_seed = util::u8ptr_to_array32(challenge_seed_ptr);
    let proof = util::u8ptr_to_vector(proof_ptr, SNARK_BYTES);

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
pub extern "C" fn status_to_string(status_code: StatusCode) -> *const libc::c_char {
    let s = match status_code {
        0 => CString::new("success"),
        10 => CString::new("failed to seal"),
        20 => CString::new("invalid replica and/or data commitment"),
        21 => CString::new("unhandled verify_seal error"),
        30 => CString::new("failed to get unsealed range"),
        40 => CString::new("failed to write to unsealed sector"),
        41 => CString::new("failed to create unsealed sector"),
        50 => CString::new("failed to open file for truncating"),
        51 => CString::new("failed to set file length"),
        60 => CString::new("could not read unsealed sector file metadata"),
        70 => CString::new("could not create unsealed sector-directory"),
        71 => CString::new("could not create unsealed sector"),
        80 => CString::new("could not create sealed sector-directory"),
        81 => CString::new("could not create sealed sector"),
        n => CString::new(format!("unknown status code {}", n)),
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
pub unsafe extern "C" fn get_unsealed_range(
    sealed_path: SectorAccess,
    output_path: SectorAccess,
    start_offset: u64,
    num_bytes: u64,
    prover_id_ptr: ProverIDPtr,
    result_ptr: GetUnsealedRangeResultPtr,
) -> StatusCode {
    let sealed_path_buf = util::pbuf_from_c(sealed_path);
    let output_path_buf = util::pbuf_from_c(output_path);
    let prover_id = util::u8ptr_to_array31(prover_id_ptr);

    match internal::get_unsealed_range(
        &sealed_path_buf,
        &output_path_buf,
        prover_id,
        start_offset,
        num_bytes,
    ) {
        Ok(num_bytes) => {
            result_ptr.write(num_bytes);
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
pub unsafe extern "C" fn get_unsealed(
    sealed_path: SectorAccess,
    output_path: SectorAccess,
    prover_id_ptr: ProverIDPtr,
) -> StatusCode {
    let sealed_path_buf = util::pbuf_from_c(sealed_path);
    let output_path_buf = util::pbuf_from_c(output_path);
    let prover_id = util::u8ptr_to_array31(prover_id_ptr);

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
    use api::sss::{
        init_disk_backed_storage, new_sealed_sector_access, new_staging_sector_access,
        write_unsealed, DiskBackedStorage,
    };
    use std::ffi::CString;
    use std::fs::{create_dir_all, File};
    use std::io::Read;
    use tempfile;

    fn rust_str_to_c_str(s: &str) -> *const libc::c_char {
        CString::new(s).unwrap().into_raw()
    }

    fn create_storage() -> *mut DiskBackedStorage {
        let staging_path = tempfile::tempdir().unwrap().path().to_owned();
        let sealed_path = tempfile::tempdir().unwrap().path().to_owned();

        create_dir_all(&staging_path).expect("failed to create staging dir");
        create_dir_all(&sealed_path).expect("failed to create sealed dir");

        let s1 = rust_str_to_c_str(&staging_path.to_str().unwrap().to_owned());
        let s2 = rust_str_to_c_str(&sealed_path.to_str().unwrap().to_owned());

        unsafe { init_disk_backed_storage(s1, s2) }
    }

    #[test]
    fn seal_verify() {
        let storage: *mut DiskBackedStorage = create_storage();
        let seal_input_path = unsafe { new_staging_sector_access(storage) };
        let seal_output_path = unsafe { new_sealed_sector_access(storage) };

        let result: [u8; 256] = [0; 256];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];

        let contents = b"hello, moto";
        let result_ptr = &mut 0u64;

        assert_eq!(0, unsafe {
            write_unsealed(
                storage,
                seal_input_path,
                &contents[0],
                contents.len(),
                result_ptr,
            )
        });

        let good_seal = unsafe {
            seal(
                seal_input_path,
                seal_output_path,
                &prover_id[0],
                &challenge_seed[0],
                &random_seed[0],
                &result[0],
            )
        };

        let good_verify = unsafe {
            verify_seal(
                &result[0],
                &result[32],
                &prover_id[0],
                &challenge_seed[0],
                &result[64],
            )
        };

        let bad_verify = unsafe {
            verify_seal(
                &result[32],
                &result[0],
                &prover_id[0],
                &challenge_seed[0],
                &result[64],
            )
        };

        assert_eq!(0, good_seal);
        assert_eq!(0, good_verify);
        assert_eq!(20, bad_verify);
    }

    #[test]
    fn seal_unsealed_roundtrip() {
        let storage = create_storage();
        let seal_input_path = unsafe { new_staging_sector_access(storage) };
        let seal_output_path = unsafe { new_sealed_sector_access(storage) };
        let get_unsealed_range_output_path = unsafe { new_staging_sector_access(storage) };

        let result: [u8; 256] = [0; 256];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];

        let contents = b"hello, moto";
        let result_ptr = &mut 0u64;

        assert_eq!(0, unsafe {
            write_unsealed(
                storage,
                seal_input_path,
                &contents[0],
                contents.len(),
                result_ptr,
            )
        });

        let good_seal = unsafe {
            seal(
                seal_input_path,
                seal_output_path,
                &prover_id[0],
                &challenge_seed[0],
                &random_seed[0],
                &result[0],
            )
        };

        assert_eq!(0, good_seal);

        let good_unsealed = unsafe {
            get_unsealed(
                seal_output_path,
                get_unsealed_range_output_path,
                &prover_id[0],
            )
        };

        assert_eq!(0, good_unsealed);

        let mut file =
            File::open(unsafe { util::pbuf_from_c(get_unsealed_range_output_path) }).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        assert_eq!(contents[..], buf[0..contents.len()]);
    }

    #[test]
    fn seal_unsealed_range_roundtrip() {
        let storage: *mut DiskBackedStorage = create_storage();
        let seal_output_path = unsafe { new_sealed_sector_access(storage) };
        let get_unsealed_range_output_path = unsafe { new_staging_sector_access(storage) };
        let seal_input_path = unsafe { new_staging_sector_access(storage) };

        let result: [u8; 256] = [0; 256];
        let prover_id: [u8; 31] = [2; 31];
        let challenge_seed: [u8; 32] = [3; 32];
        let random_seed: [u8; 32] = [4; 32];

        let contents = b"hello, moto";
        let result_ptr = &mut 0u64;

        assert_eq!(0, unsafe {
            write_unsealed(
                storage,
                seal_input_path,
                &contents[0],
                contents.len(),
                result_ptr,
            )
        });

        let good_seal = unsafe {
            seal(
                seal_input_path,
                seal_output_path,
                &prover_id[0],
                &challenge_seed[0],
                &random_seed[0],
                &result[0],
            )
        };
        assert_eq!(0, good_seal);

        let offset = 5;
        let range_length = contents.len() as u64 - offset;
        let good_unsealed = unsafe {
            get_unsealed_range(
                seal_output_path,
                get_unsealed_range_output_path,
                offset,
                range_length,
                &prover_id[0],
                result_ptr,
            )
        };

        assert_eq!(0, good_unsealed);
        assert_eq!(range_length, *result_ptr);

        let mut file =
            File::open(unsafe { util::pbuf_from_c(get_unsealed_range_output_path) }).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        assert_eq!(
            contents[(offset as usize)..],
            buf[0..(range_length as usize)]
        );
    }
}
