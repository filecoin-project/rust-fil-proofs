use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use anyhow::{format_err, Error, Result};
use semver::Version;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ApiVersion {
    V1_0_0,
    V1_1_0,
}

impl ApiVersion {
    pub fn as_semver(&self) -> Version {
        match self {
            ApiVersion::V1_0_0 => Version::new(1, 0, 0),
            ApiVersion::V1_1_0 => Version::new(1, 1, 0),
        }
    }
}

impl Debug for ApiVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let semver = self.as_semver();
        write!(f, "{}.{}.{}", semver.major, semver.minor, semver.patch)
    }
}

impl Display for ApiVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let semver = self.as_semver();
        write!(f, "{}.{}.{}", semver.major, semver.minor, semver.patch)
    }
}

impl FromStr for ApiVersion {
    type Err = Error;
    fn from_str(api_version_str: &str) -> Result<Self> {
        let api_version = Version::parse(api_version_str)?;
        match (api_version.major, api_version.minor, api_version.patch) {
            (1, 0, 0) => Ok(ApiVersion::V1_0_0),
            (1, 1, 0) => Ok(ApiVersion::V1_1_0),
            (1, 1, _) | (1, 0, _) => Err(format_err!(
                "Could not parse API Version from string (patch)"
            )),
            (1, _, _) => Err(format_err!(
                "Could not parse API Version from string (minor)"
            )),
            _ => Err(format_err!(
                "Could not parse API Version from string (major)"
            )),
        }
    }
}

#[test]
fn test_fmt() {
    assert_eq!(format!("{}", ApiVersion::V1_0_0), "1.0.0");
    assert_eq!(format!("{}", ApiVersion::V1_1_0), "1.1.0");
}

#[test]
fn test_as_semver() {
    assert_eq!(ApiVersion::V1_0_0.as_semver().major, 1);
    assert_eq!(ApiVersion::V1_1_0.as_semver().major, 1);
}
