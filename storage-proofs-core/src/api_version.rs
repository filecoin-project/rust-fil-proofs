use std::cmp::Ordering;
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use anyhow::{format_err, Error, Result};
use semver::Version;

/// The ApiVersion enum is used for mandatory changes that the network
/// must use and recognize.
///
/// New versions always require new network behaviour.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum ApiVersion {
    V1_0_0,
    V1_1_0,
    V1_2_0,
}

impl Ord for ApiVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_semver().cmp(&other.as_semver())
    }
}

impl PartialOrd for ApiVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ApiVersion {
    pub fn as_semver(&self) -> Version {
        match self {
            ApiVersion::V1_0_0 => Version::new(1, 0, 0),
            ApiVersion::V1_1_0 => Version::new(1, 1, 0),
            ApiVersion::V1_2_0 => Version::new(1, 2, 0),
        }
    }

    #[inline]
    pub fn supports_feature(&self, feat: &ApiFeature) -> bool {
        self >= &feat.first_supported_version()
            && feat
                .last_supported_version()
                .map(|v_last| self <= &v_last)
                .unwrap_or(true)
    }

    #[inline]
    pub fn supports_features(&self, feats: &[ApiFeature]) -> bool {
        feats.iter().all(|feat| self.supports_feature(feat))
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
            (1, 2, 0) => Ok(ApiVersion::V1_2_0),
            (1, 0, _) | (1, 1, _) | (1, 2, _) => Err(format_err!(
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

/// The ApiFeature enum is used for optional features that the network
/// can use and recognize, but in no way is required to be used.
///
/// New features always require new network behaviour (i.e. for proper
/// validation of others, even if not actively using)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiFeature {
    SyntheticPoRep,
}

impl ApiFeature {
    #[inline]
    pub fn first_supported_version(&self) -> ApiVersion {
        match self {
            ApiFeature::SyntheticPoRep => ApiVersion::V1_2_0,
        }
    }

    #[inline]
    pub fn last_supported_version(&self) -> Option<ApiVersion> {
        match self {
            ApiFeature::SyntheticPoRep => None,
        }
    }
}

#[test]
fn test_fmt() {
    assert_eq!(format!("{}", ApiVersion::V1_0_0), "1.0.0");
    assert_eq!(format!("{}", ApiVersion::V1_1_0), "1.1.0");
    assert_eq!(format!("{}", ApiVersion::V1_2_0), "1.2.0");
}

#[test]
fn test_as_semver() {
    assert_eq!(ApiVersion::V1_0_0.as_semver().major, 1);
    assert_eq!(ApiVersion::V1_1_0.as_semver().major, 1);
    assert_eq!(ApiVersion::V1_2_0.as_semver().major, 1);
    assert_eq!(ApiVersion::V1_0_0.as_semver().minor, 0);
    assert_eq!(ApiVersion::V1_1_0.as_semver().minor, 1);
    assert_eq!(ApiVersion::V1_2_0.as_semver().minor, 2);
    assert_eq!(ApiVersion::V1_0_0.as_semver().patch, 0);
    assert_eq!(ApiVersion::V1_1_0.as_semver().patch, 0);
    assert_eq!(ApiVersion::V1_2_0.as_semver().patch, 0);
}

#[test]
fn test_api_version_order() {
    assert!(ApiVersion::V1_0_0 < ApiVersion::V1_1_0 && ApiVersion::V1_1_0 < ApiVersion::V1_2_0);
    assert!(ApiVersion::V1_1_0 > ApiVersion::V1_0_0 && ApiVersion::V1_2_0 > ApiVersion::V1_1_0);
}

#[test]
fn test_api_feature_synthetic_porep() {
    let feature = ApiFeature::SyntheticPoRep;
    assert!(feature.first_supported_version() == ApiVersion::V1_2_0);
    assert!(feature.last_supported_version() == None);
}
