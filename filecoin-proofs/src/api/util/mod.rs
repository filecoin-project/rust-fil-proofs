use libc;
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::path::PathBuf;

// produce a C string from a Rust string
pub fn rust_str_to_c_str(s: &str) -> *const libc::c_char {
    CString::new(s).unwrap().into_raw()
}

// cast from mutable to constant reference
pub unsafe fn cast_const<'a, T>(x: *mut T) -> &'a T {
    assert!(!x.is_null(), "Object argument was null");
    (&(*x))
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
