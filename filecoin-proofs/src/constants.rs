use std::collections::HashMap;
use std::sync::{atomic::AtomicU64, atomic::AtomicU8, RwLock};

use lazy_static::lazy_static;
use storage_proofs::util::NODE_SIZE;

use crate::types::UnpaddedBytesAmount;

pub const SECTOR_SIZE_ONE_KIB: u64 = 1024;
pub const SECTOR_SIZE_16_MIB: u64 = 1 << 24;
pub const SECTOR_SIZE_256_MIB: u64 = 1 << 28;
pub const SECTOR_SIZE_1_GIB: u64 = 1 << 30;
pub const SECTOR_SIZE_32_GIB: u64 = 1 << 35;

pub const POST_CHALLENGE_COUNT: usize = 40;
pub const POST_CHALLENGED_NODES: usize = 1;

lazy_static! {
    pub static ref LAYERS: AtomicU64 = AtomicU64::new(4);
    // 5 challenges per partition
    pub static ref POREP_WINDOW_MINIMUM_CHALLENGES: AtomicU64 = AtomicU64::new(50);
    // 5 challenges per partition
    pub static ref POREP_WRAPPER_MINIMUM_CHALLENGES: AtomicU64 = AtomicU64::new(50);

    pub static ref WINDOW_DRG_DEGREE: AtomicU64 = AtomicU64::new(storage_proofs::drgraph::BASE_DEGREE as u64);
    pub static ref WINDOW_EXP_DEGREE: AtomicU64 = AtomicU64::new(storage_proofs::stacked_old::EXP_DEGREE as u64);
    pub static ref WRAPPER_EXP_DEGREE: AtomicU64 = AtomicU64::new(storage_proofs::stacked_old::EXP_DEGREE as u64);
    pub static ref DEFAULT_POREP_PROOF_PARTITIONS: AtomicU8 = AtomicU8::new(10);

    pub static ref DEFAULT_WINDOWS: RwLock<HashMap<u64, SectorInfo>> = RwLock::new({
        let mut m = HashMap::new();
        m.insert(
            SECTOR_SIZE_ONE_KIB,
            SectorInfo {
                size: SECTOR_SIZE_ONE_KIB,
                window_size: 512,
            },
        );
        m.insert(
            SECTOR_SIZE_16_MIB,
            SectorInfo {
                size: SECTOR_SIZE_16_MIB,
                window_size: 4 * 1024 * 1024,
            },
        );
        m.insert(
            SECTOR_SIZE_256_MIB,
            SectorInfo {
                size: SECTOR_SIZE_256_MIB,
                window_size: 64 * 1024 * 1024,
            },
        );
        m.insert(
            SECTOR_SIZE_1_GIB,
            SectorInfo {
                size: SECTOR_SIZE_1_GIB,
                window_size: 128 * 1024 * 1024,
            },
        );
        m.insert(
            SECTOR_SIZE_32_GIB,
            SectorInfo {
                size: SECTOR_SIZE_32_GIB,
                window_size: 128 * 1024 * 1024,
            },
        );

        m
    });
}

pub const SINGLE_PARTITION_PROOF_LEN: usize = 192;

// TODO: cfg out

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectorInfo {
    pub size: u64,
    pub window_size: u64,
}

impl SectorInfo {
    pub fn window_size_nodes(&self) -> u64 {
        self.window_size / NODE_SIZE as u64
    }
}
pub const MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR: u64 = 4;

// Bit padding causes bytes to only be aligned at every 127 bytes (for 31.75 bytes).
pub const MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR: u64 =
    (MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR * NODE_SIZE as u64) - 1;

/// The minimum size a single piece must have before padding.
pub const MIN_PIECE_SIZE: UnpaddedBytesAmount = UnpaddedBytesAmount(127);

/// The hasher used for creating comm_d.
pub type DefaultPieceHasher = storage_proofs::hasher::Sha256Hasher;

pub use storage_proofs::drgraph::DefaultTreeHasher;
