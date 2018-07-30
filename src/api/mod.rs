use libc;
use std::ffi::{CStr, CString};
use std::slice;

type CstrT = *const libc::c_char;

type SectorID = i32;
type Commitment = u32;
type ProverID = [u8; 31];
type ChallengeSeed = [u32; 8];
type RandomSeed = [u32; 8];

// arrays cannot be passed by value in C; callers instead pass a pointer to the
// head and Rust makes runtime assertions of length while marshaling
type ProverIDPtr = *const u8;
type ChallengeSeedPtr = *const u32;
type RandomSeedPtr = *const u32;
type ResultPtr = *const Commitment;

type SectorAccess = CstrT;
type SectorAccessor = extern "C" fn(i: SectorID) -> SectorAccess;

fn from_cstr(c_str: CstrT) -> String {
    unsafe {
        CStr::from_ptr(c_str)
            .to_string_lossy()
            .to_owned()
            .to_string()
    }
}

fn u32ptr_to_array8(x: *const u32) -> [u32; 8] {
    let s = unsafe { slice::from_raw_parts(x, 8).to_owned() };

    assert_eq!(
        s.len(),
        8,
        "actual len(s) = {}, expected len(s) = {}",
        s.len(),
        8
    );

    let mut out: [u32; 8] = Default::default();
    out.copy_from_slice(&s[0..8]);
    out
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

fn to_cstring(s: &str) -> CString {
    CString::new(s).unwrap()
}

const DUMMY_COMM_R: Commitment = 12345;
const DUMMY_COMM_D: Commitment = 54321;

/// Seals a sector.
///
/// # Arguments
///
/// * `sector_id`           - identity of the unsealed sector
/// * `unsealed`            - function pointer used to get access to unsealed
///                           sector
/// * `sealed`              - function pointer used to get access to sealed
///                           sector
/// * `_prover_id_ptr`      - pointer to first cell in a 31-length array of u8
/// * `_challenge_seed_ptr` - pointer to first cell in a 8-length array of u32
/// * `_random_seed_ptr`    - pointer to first cell in a 8-length array of u32
/// * `result_ptr`          - pointer to first cell in a 2-length array of u32,
///                           mutated by seal in order to pass commitments back
///                           to caller
/// ```
#[no_mangle]
pub extern "C" fn seal(
    sector_id: SectorID,
    unsealed: SectorAccessor,
    sealed: SectorAccessor,
    _prover_id_ptr: ProverIDPtr,
    _challenge_seed_ptr: ChallengeSeedPtr,
    _random_seed_ptr: RandomSeedPtr,
    result_ptr: ResultPtr,
) -> () {
    let prover_id = u8ptr_to_array31(_prover_id_ptr);
    let challenge_seed = u32ptr_to_array8(_challenge_seed_ptr);
    let random_seed = u32ptr_to_array8(_random_seed_ptr);

    let comms = seal_internal(
        sector_id,
        unsealed,
        sealed,
        prover_id,
        challenge_seed,
        random_seed,
    );

    // let caller manage this memory, preventing the need for calling back into
    // Rust code later to deallocate
    unsafe {
        *(result_ptr.offset(0 as isize) as *mut u32) = comms[0];
        *(result_ptr.offset(1 as isize) as *mut u32) = comms[1];
    };
}

fn seal_internal(
    sector_id: SectorID,
    unsealed: SectorAccessor,
    sealed: SectorAccessor,
    _prover_id: ProverID,
    _challenge_seed: ChallengeSeed,
    _random_seed: RandomSeed,
) -> [Commitment; 2] {
    let _in_path = from_cstr(unsealed(sector_id));
    let _out_path = from_cstr(sealed(sector_id));

    [DUMMY_COMM_R, DUMMY_COMM_D]
}

#[no_mangle]
pub extern "C" fn verifySeal(comm_r: Commitment, comm_d: Commitment) -> bool {
    comm_r == DUMMY_COMM_R && comm_d == DUMMY_COMM_D
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

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn sector_accessor(id: SectorID) -> SectorAccess {
        let path = format!("sector{}", id);
        println!("received path for {}: {}", id, path);
        to_cstring(&path).as_ptr()
    }

    #[test]
    fn seal_verify() {
        let result: [u32; 2] = [0; 2];
        let prover_id: [u8; 31] = [1; 31];
        let challenge_seed: [u32; 8] = [2; 8];
        let random_seed: [u32; 8] = [3; 8];

        seal(
            123,
            sector_accessor,
            sector_accessor,
            &prover_id[0],
            &challenge_seed[0],
            &random_seed[0],
            &result[0],
        );

        assert_ne!(result[0], result[1]);
        assert!(verifySeal(result[0], result[1]));
        assert!(!verifySeal(result[1], result[0]));
    }

    #[test]
    fn seal_internal_verify() {
        let comms = seal_internal(
            123,
            sector_accessor,
            sector_accessor,
            [1; 31],
            [2; 8],
            [3; 8],
        );

        assert_ne!(comms[0], comms[1]);
        assert!(verifySeal(comms[0], comms[1]));
        assert!(!verifySeal(comms[1], comms[0]));
    }
}
