use anyhow::{self, Result};
use std::str::FromStr;

#[derive(Debug, Copy, Clone)]
pub enum APIVersion {
    V1_0,
    V1_1,
}

impl FromStr for APIVersion {
    type Err = anyhow::Error;
    fn from_str(api_version: &str) -> Result<Self> {
        match api_version {
            "1" | "1-0" | "1.0" | "1_0" => Ok(APIVersion::V1_0),
            "1-1" | "1_1" | "1.1" => Ok(APIVersion::V1_1),
            _ => Err(anyhow::format_err!(
                "Could not parse API Version from string"
            )),
        }
    }
}
