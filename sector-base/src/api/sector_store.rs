use crate::api::bytes_amount::{PaddedBytesAmount, UnpaddedBytesAmount};
use crate::api::errors::SectorManagerErr;

pub trait SectorConfig {
    /// returns the number of user-provided bytes that will fit into a sector managed by this store
    fn max_unsealed_bytes_per_sector(&self) -> UnpaddedBytesAmount;

    /// returns the number of bytes in a sealed sector managed by this store
    fn sector_bytes(&self) -> PaddedBytesAmount;
}

pub trait SectorManager {
    /// provisions a new sealed sector and reports the corresponding access
    fn new_sealed_sector_access(&self) -> Result<String, SectorManagerErr>;

    /// provisions a new staging sector and reports the corresponding access
    fn new_staging_sector_access(&self) -> Result<String, SectorManagerErr>;

    /// reports the number of bytes written to an unsealed sector
    fn num_unsealed_bytes(&self, access: &str) -> Result<u64, SectorManagerErr>;

    /// sets the number of bytes in an unsealed sector identified by `access`
    fn truncate_unsealed(&self, access: &str, size: u64) -> Result<(), SectorManagerErr>;

    /// writes `data` to the staging sector identified by `access`, incrementally preprocessing `access`
    fn write_and_preprocess(
        &self,
        access: &str,
        data: &[u8],
    ) -> Result<UnpaddedBytesAmount, SectorManagerErr>;

    fn delete_staging_sector_access(&self, access: &str) -> Result<(), SectorManagerErr>;

    fn read_raw(
        &self,
        access: &str,
        start_offset: u64,
        num_bytes: UnpaddedBytesAmount,
    ) -> Result<Vec<u8>, SectorManagerErr>;
}

pub trait SectorStore {
    fn config(&self) -> &SectorConfig;
    fn manager(&self) -> &SectorManager;
}
