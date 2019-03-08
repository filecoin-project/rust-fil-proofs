# Drop struct macro derive

A derive macro to free (drop) memory for structs that are used in the FFI.

Currently only c-strings (`libc::c_char`) and arrays (represented as a pointer and a length field) are supported.

Example:

```rust
#[repr(C)]
#[derive(DropStructMacro)]
pub struct FFIStagedSectorMetadata {
    pub sector_access: *const libc::c_char,
    pub sector_id: u64,
    pub pieces_len: libc::size_t,
    pub pieces_ptr: *const FFIPieceMetadata,

    // must be one of: Pending, Failed, Sealing
    pub seal_status_code: FFISealStatus,

    // if sealing failed - here's the error
    pub seal_error_msg: *const libc::c_char,
}
```

Will automatically create:

```rust
impl Drop for FFIStagedSectorMetadata {
    fn drop(&mut self) {
        unsafe {
            free_c_str(self.sector_access as *mut libc::c_char);
            drop(Vec::from_raw_parts(
                self.pieces_ptr as *mut FFIPieceMetadata,
                self.pieces_len,
                self.pieces_len,
            ));
            free_c_str(self.seal_error_msg as *mut libc::c_char);
        };
    }
}
```

To view the generated output after the macro was applied, you can use [cargo-expand](https://github.com/dtolnay/cargo-expand):

```console
$ cd filecoin-proofs
$ cargo expand --lib api::responses
    Checking filecoin-proofs v0.1.0 (/home/vmx/src/pl/filecoin/rust-fil-proofs/filecoin-proofs)
    Finished dev [unoptimized + debuginfo] target(s) in 0.70s

pub mod responses {
    use crate::api::sector_builder::errors::SectorBuilderErr;
    use crate::api::sector_builder::SectorBuilder;
    use crate::api::API_POREP_PROOF_BYTES;
    use drop_struct_macro_derive::DropStructMacro;
    use failure::Error;
…
```

## License

MIT or Apache 2.0
