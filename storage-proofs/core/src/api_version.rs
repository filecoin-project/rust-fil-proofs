use std::str::FromStr;

use anyhow::{self, Result};
use semver::Version;

#[derive(Debug, Copy, Clone)]
pub enum ApiVersion {
    V1_0,
    V1_1,
}

impl FromStr for ApiVersion {
    type Err = anyhow::Error;
    fn from_str(api_version_str: &str) -> Result<Self> {
        let api_version = Version::parse(api_version_str)?;
        match api_version.major {
            1 => match api_version.minor {
                0 => Ok(ApiVersion::V1_0),
                1 => Ok(ApiVersion::V1_1),
                _ => Err(anyhow::format_err!(
                    "Could not parse API Version from string"
                )),
            },
            _ => Err(anyhow::format_err!(
                "Could not parse API Version from string"
            )),
        }
    }
}
