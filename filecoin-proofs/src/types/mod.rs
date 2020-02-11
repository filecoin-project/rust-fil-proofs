use serde::{Deserialize, Serialize};
use storage_proofs::hasher::Hasher;
use storage_proofs::merkle::{LCMerkleTree, MerkleTree};
use storage_proofs::stacked;

use crate::constants::{DefaultPieceHasher, DefaultTreeDomain, DefaultTreeHasher};

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
pub type PersistentAux = stacked::PersistentAux<DefaultTreeDomain>;
pub type TemporaryAux = stacked::TemporaryAux<DefaultTreeHasher, DefaultPieceHasher>;
pub type ProverId = [u8; 32];
pub type Ticket = [u8; 32];
pub type Tree = MerkleTree<DefaultTreeDomain, <DefaultTreeHasher as Hasher>::Function>;
pub type LCTree = LCMerkleTree<DefaultTreeDomain, <DefaultTreeHasher as Hasher>::Function>;

#[derive(Debug, Clone)]
pub struct SealPreCommitOutput {
    pub comm_r: Commitment,
    pub comm_d: Commitment,
}

pub type VanillaSealProof = storage_proofs::stacked::Proof<DefaultTreeHasher, DefaultPieceHasher>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealCommitPhase1Output {
    pub vanilla_proofs: Vec<Vec<VanillaSealProof>>,
    pub comm_r: Commitment,
    pub comm_d: Commitment,
    pub replica_id: <DefaultTreeHasher as Hasher>::Domain,
    pub seed: Ticket,
    pub ticket: Ticket,
}

#[derive(Clone, Debug)]
pub struct SealCommitOutput {
    pub proof: Vec<u8>,
}

pub type Labels = storage_proofs::stacked::Labels<DefaultTreeHasher>;
pub type DataTree = storage_proofs::stacked::Tree<DefaultPieceHasher>;
pub use merkletree::store::StoreConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct SealPreCommitPhase1Output {
    pub labels: Labels,
    pub config: StoreConfig,
    pub comm_d: Commitment,
}
