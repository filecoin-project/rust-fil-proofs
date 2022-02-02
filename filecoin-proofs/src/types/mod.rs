pub use merkletree::store::StoreConfig;
pub use storage_proofs_core::merkle::{MerkleProof, MerkleTreeTrait};
pub use storage_proofs_porep::stacked::{Labels, PersistentAux, TemporaryAux};

use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher};
use serde::{Deserialize, Serialize};
use storage_proofs_core::{merkle::BinaryMerkleTree, sector::SectorId};
use storage_proofs_porep::stacked;
use storage_proofs_post::fallback;

use crate::constants::DefaultPieceHasher;

mod bytes_amount;
mod hselect;
mod piece_info;
mod porep_config;
mod porep_proof_partitions;
mod post_config;
mod post_proof_partitions;
mod private_replica_info;
mod public_replica_info;
mod sector_class;
mod sector_size;
mod sector_update_config;
mod update_proof_partitions;

pub use bytes_amount::*;
pub use hselect::*;
pub use piece_info::*;
pub use porep_config::*;
pub use porep_proof_partitions::*;
pub use post_config::*;
pub use post_proof_partitions::*;
pub use private_replica_info::*;
pub use public_replica_info::*;
pub use sector_class::*;
pub use sector_size::*;
pub use sector_update_config::*;
pub use update_proof_partitions::*;

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
pub struct SealCommitPhase1Output<Tree>
where
    Tree: MerkleTreeTrait,
    <Tree::Hasher as Hasher>::Domain: Domain<Field = Fr>,
{
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

#[repr(transparent)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartitionSnarkProof(pub Vec<u8>);

pub type SnarkProof = Vec<u8>;
pub type AggregateSnarkProof = Vec<u8>;
pub type VanillaProof<Tree> = fallback::Proof<<Tree as MerkleTreeTrait>::Proof>;
pub type PartitionProof<U, V, W> = storage_proofs_update::vanilla::PartitionProof<Fr, U, V, W>;

#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
pub struct EmptySectorUpdateProof(pub Vec<u8>);

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

pub struct EmptySectorUpdateEncoded {
    pub comm_r_new: Commitment,
    pub comm_r_last_new: Commitment,
    pub comm_d_new: Commitment,
}
