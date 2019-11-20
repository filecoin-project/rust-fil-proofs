use storage_proofs::hasher::pedersen::{PedersenDomain, PedersenHasher};
use storage_proofs::hasher::Hasher;
use storage_proofs::merkle::MerkleTree;
use storage_proofs::stacked;

mod bytes_amount;
mod piece_info;
mod porep_config;
mod porep_proof_partitions;
mod post_config;
mod post_proof_partitions;
mod sector_class;
mod sector_size;

pub use self::bytes_amount::*;
pub use self::piece_info::*;
pub use self::porep_config::*;
pub use self::porep_proof_partitions::*;
pub use self::post_config::*;
pub use self::post_proof_partitions::*;
pub use self::sector_class::*;
pub use self::sector_size::*;

pub type Commitment = [u8; 32];
pub type ChallengeSeed = [u8; 32];
pub type PersistentAux = stacked::PersistentAux<PedersenDomain>;
pub type TemporaryAux = stacked::TemporaryAux<PedersenHasher, crate::constants::DefaultPieceHasher>;
pub type ProverId = [u8; 32];
pub type Ticket = [u8; 32];
pub type Tree = MerkleTree<PedersenDomain, <PedersenHasher as Hasher>::Function>;

#[derive(Debug)]
pub struct SealPreCommitOutput {
    pub comm_r: Commitment,
    pub comm_d: Commitment,
}

#[derive(Clone, Debug)]
pub struct SealCommitOutput {
    pub proof: Vec<u8>,
}
