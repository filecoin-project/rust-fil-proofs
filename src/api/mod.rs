use libc;
use std::ffi::{CStr, CString};

type CstrT = *const libc::c_char;

type SectorID = i32;
type Commitment = u32;
type ProverID = [u8; 31];

type SectorAccess = CstrT;
type SectorAccessor = extern "C" fn(i: SectorID) -> CstrT;

fn from_cstr(c_str: CstrT) -> String {
    unsafe {
        CStr::from_ptr(c_str)
            .to_string_lossy()
            .to_owned()
            .to_string()
    }
}

fn to_cstr(s: &str) -> CstrT {
    CString::new(s).unwrap().as_ptr()
}

const DUMMY_COMM_R: Commitment = 12345;
const DUMMY_COMM_D: Commitment = 54321;

#[no_mangle]
pub extern "C" fn seal(
    sector_id: SectorID,
    unsealed: SectorAccessor,
    sealed: SectorAccessor,
    _prover_id: ProverID,
    _challenge_seed: [u32; 8],
    _random_seed: [u32; 8],
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
        to_cstr(&path)
    }

    #[test]
    fn seal_verify() {
        let comms = seal(
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
