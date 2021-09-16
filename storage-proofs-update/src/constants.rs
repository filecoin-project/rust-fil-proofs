pub const PARTITIONS: usize = 16;
pub const PARTITION_BITS: usize = 4;

// The number of challenges per partition: `ceil(1375 / PARTITIONS)`.
pub const PARTITION_CHALLENGES: usize = 86;
