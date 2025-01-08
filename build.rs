fn is_compiled_for_64_bit_arch() -> bool {
    cfg!(target_pointer_width = "64")
}

fn main() {
    assert!(
        is_compiled_for_64_bit_arch(),
        "must be built for 64-bit architectures"
    );
}
