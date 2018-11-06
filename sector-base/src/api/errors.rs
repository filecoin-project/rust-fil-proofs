use api::errors::SectorManagerErr::*;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum SectorManagerErr {
    UnclassifiedError(String),
    CallerError(String),
    ReceiverError(String),
}

impl fmt::Display for SectorManagerErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            UnclassifiedError(msg) => write!(f, "UnclassifiedError({})", msg),
            CallerError(msg) => write!(f, "CallerError({})", msg),
            ReceiverError(msg) => write!(f, "ReceiverError({})", msg),
        }
    }
}

impl Error for SectorManagerErr {
    fn description(&self) -> &str {
        "an error from the SectorManager"
    }
}

#[derive(Debug)]
pub struct SBInvalidInput {
    pub error_msg: String,
}

impl Error for SBInvalidInput {
    fn description(&self) -> &str {
        "bad input"
    }
}

impl fmt::Display for SBInvalidInput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct SBInternalError {
    pub error_msg: String,
}

impl Error for SBInternalError {
    fn description(&self) -> &str {
        "unexpected, internal error"
    }
}

impl fmt::Display for SBInternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
