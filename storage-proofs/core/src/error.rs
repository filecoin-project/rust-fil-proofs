use std::any::Any;

use crate::sector::SectorId;
use bellperson::SynthesisError;

pub use anyhow::Result;

/// Custom error types
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Bytes could not be converted to Fr")]
    BadFrBytes,
    #[error("Could not create PieceInclusionProof (probably bad piece commitment: comm_p)")]
    BadPieceCommitment,
    #[error("Out of bounds access {} > {}", _0, _1)]
    OutOfBounds(usize, usize),
    #[error("mismatch of data, node_size and nodes {} != {} * {}", _0, _1, _2)]
    InvalidMerkleTreeArgs(usize, usize, usize),
    #[error("{}", _0)]
    Synthesis(#[from] SynthesisError),
    #[error("{}", _0)]
    Io(#[from] ::std::io::Error),
    #[error("tree root and commitment do not match")]
    InvalidCommitment,
    #[error("malformed input")]
    MalformedInput,
    #[error("malformed merkle tree")]
    MalformedMerkleTree,
    #[error("invalid input size")]
    InvalidInputSize,
    #[error("merkle tree generation error: {}", _0)]
    MerkleTreeGenerationError(String),
    #[error("Cannot (yet) generate inclusion proof for unaligned piece.")]
    UnalignedPiece,
    #[error("{}", _0)]
    Serde(#[from] serde_json::error::Error),
    #[error("unclassified error: {}", _0)]
    Unclassified(String),
    #[error("Missing Private Input {0} for sector {1}")]
    MissingPrivateInput(&'static str, u64),
    #[error("faulty sectors {:?}", _0)]
    FaultySectors(Vec<SectorId>),
    #[error("Invalid parameters file: {}", _0)]
    InvalidParameters(String),
}

impl From<Box<dyn Any + Send>> for Error {
    fn from(inner: Box<dyn Any + Send>) -> Error {
        Error::Unclassified(format!("{:?}", dbg!(inner)))
    }
}
