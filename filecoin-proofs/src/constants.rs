use storage_proofs::util::NODE_SIZE;

use crate::types::UnpaddedBytesAmount;

pub const POREP_MINIMUM_CHALLENGES: usize = 12; // FIXME: 8,000
pub const SINGLE_PARTITION_PROOF_LEN: usize = 192;

pub const SECTOR_SIZE_ONE_KIB: u64 = 1024;

pub const SECTOR_SIZE_16_MIB: u64 = 1 << 24;

pub const SECTOR_SIZE_256_MIB: u64 = 1 << 28;

pub const SECTOR_SIZE_1_GIB: u64 = 1 << 30;

pub const MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR: u64 = 4;

// Bit padding causes bytes to only be aligned at every 127 bytes (for 31.75 bytes).
pub const MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR: u64 =
    (MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR * NODE_SIZE as u64) - 1;

/// The minimum size a single piece must have before padding.
pub const MIN_PIECE_SIZE: UnpaddedBytesAmount = UnpaddedBytesAmount(127);

/// The hasher used for creating comm_d.
pub type DefaultPieceHasher = storage_proofs::hasher::Blake2sHasher;
