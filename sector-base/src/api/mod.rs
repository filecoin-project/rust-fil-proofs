pub mod bytes_amount;
pub mod disk_backed_storage;
pub mod errors;
pub mod porep_config;
pub mod porep_proof_partitions;
pub mod post_config;
pub mod post_proof_partitions;
pub mod sector_class;
pub mod sector_size;
pub mod sector_store;
pub mod util;

pub const SINGLE_PARTITION_PROOF_LEN: usize = 192;
