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

// Configures whether or not to use the same number of partitions as Groth16 (for production sector
// sizes).
pub const GROTH16_PARTITIONING: bool = false;

// Number of porep challenges across all partitions.
const fn challenge_count_all_partitions(sector_nodes: usize) -> usize {
    if sector_nodes >= SECTOR_NODES_32_GIB {
        180
    } else {
        2
    }
}

// Number of porep challenges per partition.
pub const fn challenge_count(sector_nodes: usize) -> usize {
    if GROTH16_PARTITIONING {
        if sector_nodes >= SECTOR_NODES_32_GIB {
            18
        } else {
            2
        }
    } else {
        1
    }
}

pub const fn partition_count(sector_nodes: usize) -> usize {
    // Groth16 partitioning uses 10 partitions for production sectors and 1 partition for test
    // sectors; Halo2 partitioning uses 1 partition per porep challenge.
    challenge_count_all_partitions(sector_nodes) / challenge_count(sector_nodes)
}

pub const fn num_layers(sector_nodes: usize) -> usize {
    if sector_nodes >= SECTOR_NODES_32_GIB {
        11
    } else {
        2
    }
}
