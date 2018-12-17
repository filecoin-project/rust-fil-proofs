extern crate libc;

use std::env;

/// How big should a fake sector be when faking proofs?
const FAKE_SECTOR_BYTES: usize = 128;

// These sizes are for SEALED sectors. They are used to calculate the values of setup parameters.
// They can be overridden by setting the corresponding environment variable (with FILECOIN_PROOFS_ prefix),
// but this is not recommended, since some sealed sector sizes are invalid. If you must set this manually,
// ensure the chosen sector size is a multiple of 32.

// Sector size, in bytes, to use when testing real proofs. (real sector store)
pub const REAL_SECTOR_SIZE: u64 = 128; // Override with FILECOIN_PROOFS_SECTOR_SIZE env var.

// Sector size, in bytes, for tests which fake sealing with a subset of the data. (fast fake sector store)
pub const FAST_SECTOR_SIZE: u64 = 1024; // Override with FILECOIN_PROOFS_FAST_SECTOR_SIZE env var.

// Sector size, in bytes, during live operation -- which also fakes sealing with a subset of the data. (slow fake sector store)
pub const SLOW_SECTOR_SIZE: u64 = 1 << 30; // Override with FILECOIN_PROOFS_SLOW_SECTOR_SIZE env var.

// The delay constants can be overridden by setting the corresponding environment variable (with FILECOIN_PROOFS_ prefix)
// For example, since SLOW_DELAY_SECONDS is used for live sealing, outside of tests,
// setting the environment variable, FILECOIN_PROOFS_SLOW_DELAY_SECONDS to 30, will result in sealing
// which takes approximately 30 seconds (with 15 seconds to get unsealed data).

// Delay, in seconds, for tests which fake sealing with a subset of the data. (fast fake sector store)
pub const FAST_DELAY_SECONDS: u32 = 10; // Override with FILECOIN_PROOFS_FAST_DELAY_SECONDS env var.

// Delay, in seconds during live operation which also fakes sealing with a subset of the data. (slow fake sector store)
pub const SLOW_DELAY_SECONDS: u32 = 0; // Override with FILECOIN_PROOFS_SLOW_DELAY_SECONDS env var.

#[derive(Debug)]
#[repr(C)]
pub enum ConfigType {
    Live = 0,
    Test = 1,
    ProofTest = 2,
}

pub struct ConfigOpts {
    dummy_parameter_cache_name: String,
    is_fake: bool,
    max_unsealed_bytes_per_sector: u64,
    proofs_sector_bytes: usize,
    sector_bytes: u64,
    simulate_delay_seconds: Option<u32>,
    uses_official_circuit: bool,
}

pub fn to_opts<T: Into<ConfigType>>(x: T) -> ConfigOpts {
    match x {
        ConfigType::Live => {
            let sector_bytes = sector_size("FILECOIN_PROOFS_SLOW_SECTOR_SIZE", SLOW_SECTOR_SIZE);

            ConfigOpts {
                dummy_parameter_cache_name: String::from("FAKE_DUMMY_API_PARAMETERS_{}"),
                is_fake: true,
                max_unsealed_bytes_per_sector: unpadded_bytes(sector_bytes),
                proofs_sector_bytes: FAKE_SECTOR_BYTES,
                sector_bytes,
                simulate_delay_seconds: Some(delay_seconds("FILECOIN_PROOFS_SLOW_DELAY_SECONDS", SLOW_DELAY_SECONDS)),
                uses_official_circuit: false,
            }
        },
        ConfigType::Test => {
            let sector_bytes = sector_size("FILECOIN_PROOFS_FAST_SECTOR_SIZE", FAST_SECTOR_SIZE);

            ConfigOpts {
                dummy_parameter_cache_name: String::from("FAKE_DUMMY_API_PARAMETERS_{}"),
                is_fake: true,
                max_unsealed_bytes_per_sector: unpadded_bytes(sector_bytes),
                proofs_sector_bytes: FAKE_SECTOR_BYTES,
                sector_bytes,
                simulate_delay_seconds: Some(delay_seconds("FILECOIN_PROOFS_FAST_DELAY_SECONDS", FAST_DELAY_SECONDS)),
                uses_official_circuit: false,
            }
        },
        ConfigType::ProofTest => {
            let sector_bytes = sector_size("FILECOIN_PROOFS_SECTOR_SIZE", REAL_SECTOR_SIZE);

            ConfigOpts {
                dummy_parameter_cache_name: String::from("REAL_DUMMY_API_PARAMETERS"),
                is_fake: false,
                max_unsealed_bytes_per_sector: unpadded_bytes(sector_bytes),
                proofs_sector_bytes: sector_bytes as usize,
                sector_bytes,
                simulate_delay_seconds: None,
                uses_official_circuit: sector_bytes == REAL_SECTOR_SIZE,
            }
        },
    }
}

fn sector_size(env_var_name: &str, default: u64) -> u64 {
    match env::var(env_var_name) {
        Ok(bytes_string) => bytes_string.parse().unwrap_or(default),
        Err(_) => default,
    }
}

fn delay_seconds(env_var_name: &str, default: u32) -> u32 {
    match env::var(env_var_name) {
        Ok(seconds_string) => seconds_string.parse().unwrap_or(default),
        Err(_) => default,
    }
}
