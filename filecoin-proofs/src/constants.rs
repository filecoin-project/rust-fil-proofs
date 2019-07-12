pub const POST_SECTORS_COUNT: usize = 2;
pub const POREP_MINIMUM_CHALLENGES: usize = 12; // FIXME: 8,000
pub const SINGLE_PARTITION_PROOF_LEN: usize = 192;

// Sector size, in bytes, for tests.
pub const TEST_SECTOR_SIZE: u64 = 1024;

// Sector size, in bytes, during live operation.
pub const LIVE_SECTOR_SIZE: u64 = 1 << 28; // 256MiB

// Bit padding causes bytes to only be aligned at every 127 bytes (for 31.75 bytes).
pub const MINIMUM_RESERVED_BYTES_FOR_PIECE_IN_FULLY_ALIGNED_SECTOR: u64 = (4 * 32) - 1;
