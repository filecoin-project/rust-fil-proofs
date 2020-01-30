pub mod blake2s;
pub mod pedersen;
pub mod poseidon;
pub mod sha256;

pub mod types;

pub use self::types::{Domain, HashFunction, Hasher};

pub use self::blake2s::Blake2sHasher;
pub use self::pedersen::PedersenHasher;
pub use self::poseidon::PoseidonHasher;
pub use self::sha256::Sha256Hasher;

/// The default hasher currently in use.
pub type DefaultTreeHasher = PoseidonHasher;
pub type DefaultTreeDomain = <DefaultTreeHasher as Hasher>::Domain;
pub type DefaultTreeHashFunction = <DefaultTreeHasher as Hasher>::Function;
