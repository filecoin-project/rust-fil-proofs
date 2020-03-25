use std::collections::HashMap;
use std::sync::RwLock;

use lazy_static::lazy_static;
use storage_proofs::hasher::Hasher;
use storage_proofs::util::NODE_SIZE;

use crate::param::{ParameterData, ParameterMap};
use crate::types::UnpaddedBytesAmount;

pub const SECTOR_SIZE_2_KIB: u64 = 2_048;
pub const SECTOR_SIZE_8_MIB: u64 = 1 << 23;
pub const SECTOR_SIZE_512_MIB: u64 = 1 << 29;
pub const SECTOR_SIZE_32_GIB: u64 = 1 << 35;

pub const ELECTION_POST_CHALLENGE_COUNT: usize = 65;
pub const ELECTION_POST_CHALLENGED_NODES: usize = 1;

pub const WINNING_POST_CHALLENGE_COUNT: usize = 1;
pub const WINNING_POST_SECTOR_COUNT: usize = 65;

pub const WINDOW_POST_CHALLENGE_COUNT: usize = 10;
pub const WINDOW_POST_SECTOR_COUNT: usize = 65; // TODO: correct value

pub const DRG_DEGREE: usize = storage_proofs::drgraph::BASE_DEGREE;
pub const EXP_DEGREE: usize = storage_proofs::porep::stacked::EXP_DEGREE;

lazy_static! {
    pub static ref PARAMETERS: ParameterMap =
        serde_json::from_str(include_str!("../parameters.json")).expect("Invalid parameters.json");
    pub static ref POREP_MINIMUM_CHALLENGES: RwLock<HashMap<u64, u64>> = RwLock::new(
        [
            (SECTOR_SIZE_2_KIB, 2),
            (SECTOR_SIZE_8_MIB, 2),
            (SECTOR_SIZE_512_MIB, 2),
            (SECTOR_SIZE_32_GIB, 138)
        ]
        .iter()
        .copied()
        .collect()
    );
    pub static ref POREP_PARTITIONS: RwLock<HashMap<u64, u8>> = RwLock::new(
        [
            (SECTOR_SIZE_2_KIB, 1),
            (SECTOR_SIZE_8_MIB, 1),
            (SECTOR_SIZE_512_MIB, 1),
            (SECTOR_SIZE_32_GIB, 9)
        ]
        .iter()
        .copied()
        .collect()
    );
    pub static ref LAYERS: RwLock<HashMap<u64, usize>> = RwLock::new(
        [
            (SECTOR_SIZE_2_KIB, 1),
            (SECTOR_SIZE_8_MIB, 2),
            (SECTOR_SIZE_512_MIB, 2),
            (SECTOR_SIZE_32_GIB, 11)
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

/// The hasher used for creating comm_d.
pub type DefaultPieceHasher = storage_proofs::hasher::Sha256Hasher;
pub type DefaultPieceDomain = <DefaultPieceHasher as Hasher>::Domain;

/// The default hasher for merkle trees currently in use.
pub type DefaultTreeHasher = storage_proofs::hasher::PoseidonHasher;
pub type DefaultTreeDomain = <DefaultTreeHasher as Hasher>::Domain;

/// Get the correct parameter data for a given cache id.
pub fn get_parameter_data(cache_id: &str) -> Option<&ParameterData> {
    PARAMETERS.get(&parameter_id(cache_id))
}

fn parameter_id(cache_id: &str) -> String {
    format!(
        "v{}-{}.params",
        storage_proofs::parameter_cache::VERSION,
        cache_id
    )
}
