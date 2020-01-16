use std::sync::{atomic::AtomicU64, atomic::AtomicU8};

use lazy_static::lazy_static;
use storage_proofs::util::NODE_SIZE;

use crate::param::ParameterMap;
use crate::types::UnpaddedBytesAmount;

pub const SECTOR_SIZE_ONE_KIB: u64 = 1024;
pub const SECTOR_SIZE_16_MIB: u64 = 1 << 24;
pub const SECTOR_SIZE_256_MIB: u64 = 1 << 28;
pub const SECTOR_SIZE_1_GIB: u64 = 1 << 30;
pub const SECTOR_SIZE_32_GIB: u64 = 1 << 35;

pub const POST_CHALLENGE_COUNT: usize = 40;
pub const POST_CHALLENGED_NODES: usize = 1;

lazy_static! {
    pub static ref LAYERS: AtomicU64 = AtomicU64::new(11);
    pub static ref POREP_MINIMUM_CHALLENGES: AtomicU64 = AtomicU64::new(50);
    pub static ref DRG_DEGREE: AtomicU64 =
        AtomicU64::new(storage_proofs::drgraph::BASE_DEGREE as u64);
    pub static ref EXP_DEGREE: AtomicU64 =
        AtomicU64::new(storage_proofs::stacked::EXP_DEGREE as u64);
    pub static ref DEFAULT_POREP_PROOF_PARTITIONS: AtomicU8 = AtomicU8::new(10);
    pub static ref PARAMETERS: ParameterMap =
        serde_json::from_str(include_str!("../parameters.json")).expect("Invalid parameters.json");
}

/// The size of a single snark proof.
pub const SINGLE_PARTITION_PROOF_LEN: usize = 192;

pub const MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR: u64 = 4;

// Bit padding causes bytes to only be aligned at every 127 bytes (for 31.75 bytes).
pub const MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR: u64 =
    (MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR * NODE_SIZE as u64) - 1;

/// The minimum size a single piece must have before padding.
pub const MIN_PIECE_SIZE: UnpaddedBytesAmount = UnpaddedBytesAmount(127);

/// The hasher used for creating comm_d.
pub type DefaultPieceHasher = storage_proofs::hasher::Sha256Hasher;

pub use storage_proofs::drgraph::DefaultTreeHasher;
