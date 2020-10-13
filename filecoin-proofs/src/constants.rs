use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use storage_proofs_core::util::NODE_SIZE;

use crate::types::UnpaddedBytesAmount;

pub const SECTOR_SIZE_2_KIB: u64 = 1 << 11;
pub const SECTOR_SIZE_4_KIB: u64 = 1 << 12;
pub const SECTOR_SIZE_16_KIB: u64 = 1 << 14;
pub const SECTOR_SIZE_32_KIB: u64 = 1 << 15;
pub const SECTOR_SIZE_8_MIB: u64 = 1 << 23;
pub const SECTOR_SIZE_16_MIB: u64 = 1 << 24;
pub const SECTOR_SIZE_512_MIB: u64 = 1 << 29;
pub const SECTOR_SIZE_1_GIB: u64 = 1 << 30;
pub const SECTOR_SIZE_32_GIB: u64 = 1 << 35;
pub const SECTOR_SIZE_64_GIB: u64 = 1 << 36;

pub const WINNING_POST_CHALLENGE_COUNT: usize = 66;
pub const WINNING_POST_SECTOR_COUNT: usize = 1;

pub const WINDOW_POST_CHALLENGE_COUNT: usize = 10;

pub const DRG_DEGREE: usize = storage_proofs_core::drgraph::BASE_DEGREE;
pub const EXP_DEGREE: usize = storage_proofs_porep::stacked::EXP_DEGREE;

lazy_static! {
    pub static ref POREP_MINIMUM_CHALLENGES: RwLock<HashMap<u64, u64>> = RwLock::new(
        [
            (SECTOR_SIZE_2_KIB, 2),
            (SECTOR_SIZE_4_KIB, 2),
            (SECTOR_SIZE_16_KIB, 2),
            (SECTOR_SIZE_32_KIB, 2),
            (SECTOR_SIZE_8_MIB, 2),
            (SECTOR_SIZE_16_MIB, 2),
            (SECTOR_SIZE_512_MIB, 2),
            (SECTOR_SIZE_1_GIB, 2),
            (SECTOR_SIZE_32_GIB, 176),
            (SECTOR_SIZE_64_GIB, 176),
        ]
        .iter()
        .copied()
        .collect()
    );
    pub static ref POREP_PARTITIONS: RwLock<HashMap<u64, u8>> = RwLock::new(
        [
            (SECTOR_SIZE_2_KIB, 1),
            (SECTOR_SIZE_4_KIB, 1),
            (SECTOR_SIZE_16_KIB, 1),
            (SECTOR_SIZE_32_KIB, 1),
            (SECTOR_SIZE_8_MIB, 1),
            (SECTOR_SIZE_16_MIB, 1),
            (SECTOR_SIZE_512_MIB, 1),
            (SECTOR_SIZE_1_GIB, 1),
            (SECTOR_SIZE_32_GIB, 10),
            (SECTOR_SIZE_64_GIB, 10),
        ]
        .iter()
        .copied()
        .collect()
    );
    pub static ref LAYERS: RwLock<HashMap<u64, usize>> = RwLock::new(
        [
            (SECTOR_SIZE_2_KIB, 2),
            (SECTOR_SIZE_4_KIB, 2),
            (SECTOR_SIZE_16_KIB, 2),
            (SECTOR_SIZE_32_KIB, 2),
            (SECTOR_SIZE_8_MIB, 2),
            (SECTOR_SIZE_16_MIB, 2),
            (SECTOR_SIZE_512_MIB, 2),
            (SECTOR_SIZE_1_GIB, 2),
            (SECTOR_SIZE_32_GIB, 11),
            (SECTOR_SIZE_64_GIB, 11),
        ]
        .iter()
        .copied()
        .collect()
    );
    // These numbers must match those used for Window PoSt scheduling in the miner actor.
    // Please coordinate changes with actor code.
    // https://github.com/filecoin-project/specs-actors/blob/master/actors/abi/sector.go
    pub static ref WINDOW_POST_SECTOR_COUNT: RwLock<HashMap<u64, usize>> = RwLock::new(
        [
            (SECTOR_SIZE_2_KIB, 2),
            (SECTOR_SIZE_4_KIB, 2),
            (SECTOR_SIZE_16_KIB, 2),
            (SECTOR_SIZE_32_KIB, 2),
            (SECTOR_SIZE_8_MIB, 2),
            (SECTOR_SIZE_16_MIB, 2),
            (SECTOR_SIZE_512_MIB, 2),
            (SECTOR_SIZE_1_GIB, 2),
            (SECTOR_SIZE_32_GIB, 2349), // this gives 125,279,217 constraints, fitting in a single partition
            (SECTOR_SIZE_64_GIB, 2300), // this gives 129,887,900 constraints, fitting in a single partition
        ]
        .iter()
        .copied()
        .collect()
    );
}

/// The size of a single snark proof.
pub const SINGLE_PARTITION_PROOF_LEN: usize = 192;

pub const MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR: u64 = 4;

// Bit padding causes bytes to only be aligned at every 127 bytes (for 31.75 bytes).
pub const MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR: u64 =
    (MINIMUM_RESERVED_LEAVES_FOR_PIECE_IN_SECTOR * NODE_SIZE as u64) - 1;

/// The minimum size a single piece must have before padding.
pub const MIN_PIECE_SIZE: UnpaddedBytesAmount = UnpaddedBytesAmount(127);
