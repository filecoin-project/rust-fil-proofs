extern crate libc;

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::path::PathBuf;

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum FFIResponseStatus {
    NoError = 0,
    UnclassifiedError = 1,
    CallerError = 2,
    ReceiverError = 3,
}

// produce a C string from a Rust string
pub fn rust_str_to_c_str(s: &str) -> *const libc::c_char {
    CString::new(s).unwrap().into_raw()
}

// return a forgotten raw pointer to something of type T
pub fn raw_ptr<T>(thing: T) -> *mut T {
    Box::into_raw(Box::new(thing))
}

// transmutes a C string to a copy-on-write Rust string
pub unsafe fn c_str_to_rust_str<'a>(x: *const libc::c_char) -> Cow<'a, str> {
    use std::borrow::Cow;
    if x.is_null() {
        Cow::from("")
    } else {
        CStr::from_ptr(x).to_string_lossy()
    }
}

// cast from mutable to constant reference
pub unsafe fn cast_const<'a, T>(x: *mut T) -> &'a T {
    assert!(!x.is_null(), "Object argument was null");
    (&(*x))
}

// transmutes a C string to a PathBuf
pub unsafe fn c_str_to_pbuf(x: *const libc::c_char) -> PathBuf {
    PathBuf::from(String::from(c_str_to_rust_str(x)))
}
