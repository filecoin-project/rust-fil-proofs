//! An implementation of the [SHA-2][1] cryptographic hash algorithms.

// Give relevant error messages if the user tries to enable AArch64 asm on unsupported platforms.

#![deny(clippy::all, clippy::perf, clippy::correctness)]
#![allow(clippy::unreadable_literal)]

mod consts;

mod platform;
mod sha256;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod sha256_intrinsics;
mod sha256_utils;

pub use digest::Digest;
pub use sha256::Sha256;
