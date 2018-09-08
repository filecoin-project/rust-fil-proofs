use libc;
use std::borrow::Cow;
use std::ffi::CStr;
use std::path::PathBuf;
use std::slice;

// cast from mutable to constant reference
pub unsafe fn cast_const<'a, T>(x: *mut T) -> &'a T {
    assert!(!x.is_null(), "Object argument was null");
    (&(*x))
}

pub unsafe fn u8ptr_to_array32(x: *const u8) -> [u8; 32] {
    let s = slice::from_raw_parts(x, 32).to_owned();

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

pub unsafe fn u8ptr_to_array31(x: *const u8) -> [u8; 31] {
    let s = slice::from_raw_parts(x, 31).to_owned();

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

pub unsafe fn u8ptr_to_vector(x: *const u8, length: usize) -> Vec<u8> {
    let s = slice::from_raw_parts(x, length).to_owned();

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

// transmutes a C string to a copy-on-write Rust string
pub unsafe fn str_from_c<'a>(x: *const libc::c_char) -> Cow<'a, str> {
    use std::borrow::Cow;
    if x.is_null() {
        Cow::from("")
    } else {
        CStr::from_ptr(x).to_string_lossy()
    }
}

// transmutes a C string to a PathBuf
pub unsafe fn pbuf_from_c(x: *const libc::c_char) -> PathBuf {
    PathBuf::from(String::from(str_from_c(x)))
}
