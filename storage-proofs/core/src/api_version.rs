use std::fmt;
use std::str::FromStr;

use anyhow::{self, Result};
use semver::Version;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ApiVersion {
    V1_0_0,
    V1_1_0,
}

impl fmt::Debug for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ApiVersion::V1_0_0 => write!(f, "1.0.0"),
            ApiVersion::V1_1_0 => write!(f, "1.1.0"),
        }
    }
}

impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ApiVersion::V1_0_0 => write!(f, "1.0.0"),
            ApiVersion::V1_1_0 => write!(f, "1.1.0"),
        }
    }
}

impl FromStr for ApiVersion {
    type Err = anyhow::Error;
    fn from_str(api_version_str: &str) -> Result<Self> {
        let api_version = Version::parse(api_version_str)?;
        match (api_version.major, api_version.minor, api_version.patch) {
            (1, 0, 0) => Ok(ApiVersion::V1_0_0),
            (1, 1, 0) => Ok(ApiVersion::V1_1_0),
            (1, 1, _) | (1, 0, _) => Err(anyhow::format_err!(
                "Could not parse API Version from string (patch)"
            )),
            (1, _, _) => Err(anyhow::format_err!(
                "Could not parse API Version from string (minor)"
            )),
            _ => Err(anyhow::format_err!(
                "Could not parse API Version from string (major)"
            )),
        }
    }
}
