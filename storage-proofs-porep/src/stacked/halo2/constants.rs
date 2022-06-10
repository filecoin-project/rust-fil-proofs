pub use storage_proofs_core::drgraph::BASE_DEGREE as DRG_PARENTS;

pub use crate::stacked::{vanilla::TOTAL_PARENTS as REPEATED_PARENTS, EXP_DEGREE as EXP_PARENTS};

pub const SECTOR_NODES_2_KIB: usize = 1 << 6;
pub const SECTOR_NODES_4_KIB: usize = 1 << 7;
pub const SECTOR_NODES_8_KIB: usize = 1 << 8;
pub const SECTOR_NODES_16_KIB: usize = 1 << 9;
pub const SECTOR_NODES_32_KIB: usize = 1 << 10;
pub const SECTOR_NODES_8_MIB: usize = 1 << 18;
pub const SECTOR_NODES_16_MIB: usize = 1 << 19;
pub const SECTOR_NODES_512_MIB: usize = 1 << 24;
pub const SECTOR_NODES_32_GIB: usize = 1 << 30;
pub const SECTOR_NODES_64_GIB: usize = 1 << 31;

// Each field element label is decomposed into eight `u32` words.
pub const LABEL_WORD_LEN: usize = 8;

// The number of `u32` words produced by repeating parent labels.
pub const REPEATED_PARENT_LABELS_WORD_LEN: usize = REPEATED_PARENTS * LABEL_WORD_LEN;

// Labeling preimage length in sha256 32-bit words: replica-id (256 bits) | layer (32 bits) |
// challenge (64 bits) | 5x zeros (160 bits) | parent labels (9472 bits).
pub const LABEL_PREIMAGE_WORD_LEN: usize = 8 + 1 + 2 + 5 + REPEATED_PARENT_LABELS_WORD_LEN;

pub const fn challenge_count<const SECTOR_NODES: usize>() -> usize {
    match SECTOR_NODES {
        SECTOR_NODES_32_GIB | SECTOR_NODES_64_GIB => 176,
        _ => 2,
    }
}

pub const fn partition_count<const SECTOR_NODES: usize>() -> usize {
    match SECTOR_NODES {
        SECTOR_NODES_32_GIB | SECTOR_NODES_64_GIB => 10,
        _ => 1,
    }
}

pub const fn num_layers<const SECTOR_NODES: usize>() -> usize {
    match SECTOR_NODES {
        SECTOR_NODES_32_GIB | SECTOR_NODES_64_GIB => 11,
        _ => 2,
    }
}
