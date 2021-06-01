pub use merkletree::store::StoreConfig;
pub use storage_proofs_core::merkle::{MerkleProof, MerkleTreeTrait};
pub use storage_proofs_porep::stacked::{Labels, PersistentAux, TemporaryAux};

use filecoin_hashers::Hasher;
use serde::{Deserialize, Serialize};
use storage_proofs_core::{merkle::BinaryMerkleTree, sector::SectorId};
use storage_proofs_porep::stacked;
use storage_proofs_post::fallback;

use crate::constants::DefaultPieceHasher;

mod bytes_amount;
mod piece_info;
mod porep_config;
mod porep_proof_partitions;
mod post_config;
mod post_proof_partitions;
mod private_replica_info;
mod public_replica_info;
mod sector_class;
mod sector_size;

pub use bytes_amount::*;
pub use piece_info::*;
pub use porep_config::*;
pub use porep_proof_partitions::*;
pub use post_config::*;
pub use post_proof_partitions::*;
pub use private_replica_info::*;
pub use public_replica_info::*;
pub use sector_class::*;
pub use sector_size::*;

pub type Commitment = [u8; 32];
pub type ChallengeSeed = [u8; 32];
pub type ProverId = [u8; 32];
pub type Ticket = [u8; 32];
pub type DataTree = BinaryMerkleTree<DefaultPieceHasher>;

/// Arity for oct trees, used for comm_r_last.
pub const OCT_ARITY: usize = 8;

/// Arity for binary trees, used for comm_d.
pub const BINARY_ARITY: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealPreCommitOutput {
    pub comm_r: Commitment,
    pub comm_d: Commitment,
}

pub type VanillaSealProof<Tree> = stacked::Proof<Tree, DefaultPieceHasher>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealCommitPhase1Output<Tree: MerkleTreeTrait> {
    #[serde(bound(
        serialize = "VanillaSealProof<Tree>: Serialize",
        deserialize = "VanillaSealProof<Tree>: Deserialize<'de>"
    ))]
    pub vanilla_proofs: Vec<Vec<VanillaSealProof<Tree>>>,
    pub comm_r: Commitment,
    pub comm_d: Commitment,
    pub replica_id: <Tree::Hasher as Hasher>::Domain,
    pub seed: Ticket,
    pub ticket: Ticket,
}

#[derive(Clone, Debug)]
pub struct SealCommitOutput {
    pub proof: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealPreCommitPhase1Output<Tree: MerkleTreeTrait> {
    #[serde(bound(
        serialize = "Labels<Tree>: Serialize",
        deserialize = "Labels<Tree>: Deserialize<'de>"
    ))]
    pub labels: Labels<Tree>,
    pub config: StoreConfig,
    pub comm_d: Commitment,
}

pub type SnarkProof = Vec<u8>;
pub type AggregateSnarkProof = Vec<u8>;
pub type VanillaProof<Tree> = fallback::Proof<<Tree as MerkleTreeTrait>::Proof>;

// This FallbackPoStSectorProof is used during Fallback PoSt, but
// contains only Vanilla proof information and is not a full Fallback
// PoSt proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FallbackPoStSectorProof<Tree: MerkleTreeTrait> {
    pub sector_id: SectorId,
    pub comm_r: <Tree::Hasher as Hasher>::Domain,
    #[serde(bound(
        serialize = "VanillaProof<Tree>: Serialize",
        deserialize = "VanillaProof<Tree>: Deserialize<'de>"
    ))]
    pub vanilla_proof: VanillaProof<Tree>, // Has comm_c, comm_r_last, inclusion_proofs
}
