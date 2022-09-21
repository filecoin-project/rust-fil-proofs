// Configures whether or not to use the same number of partitions as Groth16 (for production sector
// sizes).
pub const GROTH16_PARTITIONING: bool = false;

// The number of halo2 partition proofs for the given sector size.
pub const fn partition_count(sector_nodes: usize) -> usize {
    use crate::constants::{challenge_count, partition_count};
    if GROTH16_PARTITIONING {
        partition_count(sector_nodes)
    } else {
        // Partition count is the total number of groth16 challenges.
        partition_count(sector_nodes) * challenge_count(sector_nodes)
    }
}

// The number of partition bits in a partition's public inputs.
pub const fn partition_bit_len(sector_nodes: usize) -> usize {
    if GROTH16_PARTITIONING {
        partition_count(sector_nodes).trailing_zeros() as usize
    } else {
        0
    }
}

// The number of challenge's per halo2 partition proof.
pub const fn challenge_count(sector_nodes: usize) -> usize {
    if GROTH16_PARTITIONING {
        crate::constants::challenge_count(sector_nodes)
    } else {
        1
    }
}

// The number of leafs in each partition's apex-tree.
pub const fn apex_leaf_count(sector_nodes: usize) -> usize {
    if GROTH16_PARTITIONING {
        crate::constants::apex_leaf_count(sector_nodes)
    } else {
        0
    }
}

pub const fn apex_leaf_bit_len(sector_nodes: usize) -> usize {
    if GROTH16_PARTITIONING {
        crate::constants::apex_leaf_count(sector_nodes).trailing_zeros() as usize
    } else {
        0
    }
}
