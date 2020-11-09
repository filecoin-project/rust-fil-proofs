use filecoin_hashers::Hasher;
use serde::{Deserialize, Serialize};
use storage_proofs::porep::stacked;
use storage_proofs::post::fallback::*;
use storage_proofs::sector::*;

use crate::constants::*;

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
pub use stacked::PersistentAux;
pub use stacked::TemporaryAux;
pub type ProverId = [u8; 32];
pub type Ticket = [u8; 32];

pub use storage_proofs::porep::stacked::Labels;
pub type DataTree = storage_proofs::merkle::BinaryMerkleTree<DefaultPieceHasher>;

pub use storage_proofs::merkle::MerkleProof;
pub use storage_proofs::merkle::MerkleTreeTrait;

/// Arity for oct trees, used for comm_r_last.
pub const OCT_ARITY: usize = 8;

/// Arity for binary trees, used for comm_d.
pub const BINARY_ARITY: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealPreCommitOutput {
    pub comm_r: Commitment,
    pub comm_d: Commitment,
}

pub type VanillaSealProof<Tree> = storage_proofs::porep::stacked::Proof<Tree, DefaultPieceHasher>;

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

pub use merkletree::store::StoreConfig;

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
pub type VanillaProof<Tree> = Proof<<Tree as MerkleTreeTrait>::Proof>;

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
