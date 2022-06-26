use std::any::TypeId;

pub use merkletree::store::StoreConfig;
pub use storage_proofs_core::merkle::{MerkleProof, MerkleTreeTrait};
pub use storage_proofs_porep::stacked::{Labels, PersistentAux, TemporaryAux};

use blstrs::Scalar as Fr;
use filecoin_hashers::{Domain, Hasher};
use halo2_proofs::{arithmetic::FieldExt, pasta::{Fp, Fq}};
use serde::{Deserialize, Serialize};
use storage_proofs_core::{merkle::BinaryMerkleTree, sector::SectorId};
use storage_proofs_porep::stacked;
use storage_proofs_post::fallback;

use crate::constants::{DefaultPieceDomain, DefaultPieceHasher};

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
pub type DataTree<F> = BinaryMerkleTree<DefaultPieceHasher<F>>;

/// Arity for oct trees, used for comm_r_last.
pub const OCT_ARITY: usize = 8;

/// Arity for binary trees, used for comm_d.
pub const BINARY_ARITY: usize = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealPreCommitOutput {
    pub comm_r: Commitment,
    pub comm_d: Commitment,
}

pub type VanillaSealProof<Tree> = stacked::Proof<
    Tree,
    DefaultPieceHasher<<<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain as Domain>::Field>,
>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealCommitPhase1Output<Tree>
where
    Tree: MerkleTreeTrait,
    DefaultPieceHasher<<<Tree::Hasher as Hasher>::Domain as Domain>::Field>: Hasher,
    DefaultPieceDomain<<<Tree::Hasher as Hasher>::Domain as Domain>::Field>:
        Domain<Field = <<Tree::Hasher as Hasher>::Domain as Domain>::Field>,
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

// The circuit public inputs for a partition.
#[derive(Clone)]
pub enum CircuitPublicInputs {
    Groth(Vec<Fr>),
    HaloPallas(Vec<Vec<Fp>>),
    HaloVesta(Vec<Vec<Fq>>),
}

impl From<Vec<Fr>> for CircuitPublicInputs {
    fn from(pub_inputs: Vec<Fr>) -> Self {
        CircuitPublicInputs::Groth(pub_inputs)
    }
}

impl<F: FieldExt> From<Vec<Vec<F>>> for CircuitPublicInputs {
    fn from(pub_inputs: Vec<Vec<F>>) -> Self {
        let field = TypeId::of::<F>();
        if field == TypeId::of::<Fp>() {
            unsafe { CircuitPublicInputs::HaloPallas(std::mem::transmute(pub_inputs)) }
        } else if field == TypeId::of::<Fq>() {
            unsafe { CircuitPublicInputs::HaloVesta(std::mem::transmute(pub_inputs)) }
        } else {
            panic!("public inputs field must be pallas or vesta")
        }
    }
}

impl Into<Vec<Fr>> for CircuitPublicInputs {
    fn into(self) -> Vec<Fr> {
        match self {
            CircuitPublicInputs::Groth(pub_inputs) => pub_inputs,
            CircuitPublicInputs::HaloPallas(_) =>
                panic!("cannot convert halo2-pallas public inputs into groth16 public inputs"),
            CircuitPublicInputs::HaloVesta(_) =>
                panic!("cannot convert halo2-vesta public inputs into groth16 public inputs"),
        }
    }
}

impl<F: FieldExt> Into<Vec<Vec<F>>> for CircuitPublicInputs {
    fn into(self) -> Vec<Vec<F>> {
        match self {
            CircuitPublicInputs::Groth(_) =>
                panic!("cannot convert halo2 public inputs into groth16 public inputs"),
            CircuitPublicInputs::HaloPallas(pub_inputs) => {
                assert_eq!(
                    TypeId::of::<F>(),
                    TypeId::of::<Fp>(),
                    "cannot convert halo2-pallas public inputs into halo2-vesta public inputs"
                );
                unsafe { std::mem::transmute(pub_inputs) }
            }
            CircuitPublicInputs::HaloVesta(pub_inputs) => {
                assert_eq!(
                    TypeId::of::<F>(),
                    TypeId::of::<Fq>(),
                    "cannot convert halo2-vesta public inputs into halo2-pallas public inputs"
                );
                unsafe { std::mem::transmute(pub_inputs) }
            }
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartitionSnarkProof(pub Vec<u8>);

pub type SnarkProof = Vec<u8>;
pub type AggregateSnarkProof = Vec<u8>;
pub type VanillaProof<Tree> = fallback::Proof<<Tree as MerkleTreeTrait>::Proof>;
pub type PartitionProof<F, U, V, W> = storage_proofs_update::vanilla::PartitionProof<F, U, V, W>;

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
