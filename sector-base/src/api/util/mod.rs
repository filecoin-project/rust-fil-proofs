use libc;
use rand::{thread_rng, Rng};
use std::ffi::{CStr, CString};
use std::path::PathBuf;

// produce a C string from a Rust string
pub fn rust_str_to_c_str(s: &str) -> *const libc::c_char {
    CString::new(s).unwrap().into_raw()
}

// produce a Rust string from a C string
pub unsafe fn c_str_to_rust_str(x: *const libc::c_char) -> String {
    if x.is_null() {
        String::new()
    } else {
        CStr::from_ptr(x).to_string_lossy().to_string()
    }
}

// creates a string of size len containing uppercase alpha-chars
pub fn rand_alpha_string(len: u8) -> String {
    let mut str = String::new();
    let mut rng = thread_rng();

    for _ in 0..len {
        let ch = rng.gen_range(b'A', b'Z') as char;
        str.push(ch);
    }

    str
}

// transmutes a C string to a PathBuf
pub unsafe fn pbuf_from_c(x: *const libc::c_char) -> PathBuf {
    PathBuf::from(c_str_to_rust_str(x))
}

// return a forgotten raw pointer to something of type T.
pub fn raw_ptr<T>(thing: T) -> *mut T {
    Box::into_raw(Box::new(thing))
}
