use std::any::Any;

use bellperson::SynthesisError;

pub type Result<T> = ::std::result::Result<T, Error>;

/// Custom error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Bytes could not be converted to Fr")]
    BadFrBytes,
    #[fail(
        display = "Could not create PieceInclusionProof (probably bad piece commitment: comm_p)"
    )]
    BadPieceCommitment,
    #[fail(display = "Out of bounds access {} > {}", _0, _1)]
    OutOfBounds(usize, usize),
    #[fail(
        display = "mismatch of data, node_size and nodes {} != {} * {}",
        _0, _1, _2
    )]
    InvalidMerkleTreeArgs(usize, usize, usize),
    #[fail(display = "{}", _0)]
    Synthesis(#[cause] SynthesisError),
    #[fail(display = "{}", _0)]
    Io(#[cause] ::std::io::Error),
    #[fail(display = "tree root and commitment do not match")]
    InvalidCommitment,
    #[fail(display = "malformed input")]
    MalformedInput,
    #[fail(display = "malformed merkle tree")]
    MalformedMerkleTree,
    #[fail(display = "invalid input size")]
    InvalidInputSize,
    #[fail(display = "merkle tree generation error: {}", _0)]
    MerkleTreeGenerationError(String),
    #[fail(display = "Cannot (yet) generate inclusion proof for unaligned piece.")]
    UnalignedPiece,
    #[fail(display = "{}", _0)]
    Serde(#[cause] serde_json::error::Error),
    #[fail(display = "unclassified error: {}", _0)]
    Unclassified(String),
}

impl From<SynthesisError> for Error {
    fn from(inner: SynthesisError) -> Error {
        Error::Synthesis(inner)
    }
}

impl From<::std::io::Error> for Error {
    fn from(inner: ::std::io::Error) -> Error {
        Error::Io(inner)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(inner: serde_json::error::Error) -> Error {
        Error::Serde(inner)
    }
}

impl From<Box<dyn Any + Send>> for Error {
    fn from(inner: Box<dyn Any + Send>) -> Error {
        Error::Unclassified(format!("{:?}", dbg!(inner)))
    }
}
