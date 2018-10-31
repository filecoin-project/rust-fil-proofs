extern crate ffi_toolkit;
extern crate libc;

use ffi_toolkit::{c_str_to_rust_str, rust_str_to_c_str};

#[repr(C)]
struct CSectorBuilder(libc::c_void);

#[link(name = "sector_base")]
extern "C" {
    fn init_sector_builder(
        last_used_sector_id: u64,
        metadata_dir: *const libc::c_char,
        prover_id: &[u8; 31],
        sealed_sector_dir: *const libc::c_char,
        staged_sector_dir: *const libc::c_char,
    ) -> *mut CSectorBuilder;

    fn debug_state(ptr: *mut CSectorBuilder) -> *const libc::c_char;

    fn destroy_sector_builder(ptr: *mut CSectorBuilder);
}

fn main() {
    unsafe {
        let prover_id: [u8; 31] = [0; 31];

        let sb = init_sector_builder(
            123,
            rust_str_to_c_str("metadata"),
            &prover_id,
            rust_str_to_c_str("sealed"),
            rust_str_to_c_str("staged"),
        );

        let message = c_str_to_rust_str(debug_state(sb));

        assert!(message.contains("SectorBuilder"));

        destroy_sector_builder(sb);
    }
}
