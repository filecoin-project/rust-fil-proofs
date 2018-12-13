use bellman::SynthesisError;

pub type Result<T> = ::std::result::Result<T, Error>;

/// Custom error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Bytes could not be converted to Fr")]
    BadFrBytes,
    #[fail(display = "Out of bounds access {} > {}", _0, _1)]
    OutOfBounds(usize, usize),
    #[fail(
        display = "mismatch of data, node_size and nodes {} != {} * {}",
        _0, _1, _2
    )]
    InvalidMerkleTreeArgs(usize, usize, usize),
    #[fail(display = "invalid node size ({}), must be 16, 32 or 64", _0)]
    InvalidNodeSize(usize),
    #[fail(display = "{}", _0)]
    Synthesis(#[cause] SynthesisError),
    #[fail(display = "{}", _0)]
    Io(#[cause] ::std::io::Error),
    #[fail(display = "tree root and commitment do not match")]
    InvalidCommitment,
    #[fail(display = "malformed input")]
    MalformedInput,
    #[fail(display = "invalid input size")]
    InvalidInputSize,
    #[fail(display = "merkle tree generation error: {}", _0)]
    MerkleTreeGenerationError(String),
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
