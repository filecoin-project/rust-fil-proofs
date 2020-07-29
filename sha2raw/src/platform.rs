#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Platform {
    Portable,
    #[cfg(feature = "asm")]
    Asm,
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    Sha,
}

#[derive(Clone, Copy, Debug)]
pub struct Implementation(Platform);

impl Implementation {
    pub fn detect() -> Self {
        // Try the different implementations in order of how fast/modern they are.
        #[cfg(target_arch = "x86_64")]
        {
            if let Some(sha_impl) = Self::sha_if_supported() {
                return sha_impl;
            }
        }
        #[cfg(feature = "asm")]
        {
            if let Some(asm_impl) = Self::asm_if_supported() {
                return asm_impl;
            }
        }

        Self::portable()
    }

    pub fn portable() -> Self {
        Implementation(Platform::Portable)
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(unreachable_code)]
    pub fn sha_if_supported() -> Option<Self> {
        // Use raw_cpuid instead of is_x86_feature_detected, to ensure the check
        // never happens at compile time.
        let is_runtime_ok = cpuid_bool::cpuid_bool!("sha");

        #[cfg(target_feature = "sha")]
        {
            if !is_runtime_ok {
                println!("WARN: sha-ni not available, falling back");
            }
        }

        // Make sure this computer actually supports it
        if is_runtime_ok {
            return Some(Implementation(Platform::Sha));
        }

        None
    }

    #[cfg(feature = "asm")]
    pub fn asm_if_supported() -> Option<Self> {
        Some(Implementation(Platform::Asm))
    }

    #[inline]
    pub fn compress256(self, state: &mut [u32; 8], blocks: &[&[u8]]) {
        match self.0 {
            Platform::Portable => {
                use crate::sha256_utils;
                sha256_utils::compress256(state, blocks);
            }
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            Platform::Sha => {
                use crate::sha256_intrinsics;
                unsafe { sha256_intrinsics::compress256(state, blocks) };
            }
            #[cfg(feature = "asm")]
            Platform::Asm => {
                let mut buffer = [0u8; 64];
                for block in blocks.chunks(2) {
                    buffer[..32].copy_from_slice(&block[0]);
                    buffer[32..].copy_from_slice(&block[1]);
                    sha2_asm::compress256(state, &buffer);
                }
            }
        }
    }
}
