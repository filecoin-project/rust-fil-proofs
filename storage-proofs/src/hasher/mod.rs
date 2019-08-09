pub mod blake2s;
pub mod pedersen;

mod types;

pub use self::types::{Domain, HashFunction, Hasher};

pub use self::blake2s::Blake2sHasher;
pub use self::pedersen::PedersenHasher;
