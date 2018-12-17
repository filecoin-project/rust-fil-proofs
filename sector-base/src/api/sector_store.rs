use crate::api::errors::SectorManagerErr;

pub trait SectorManager {
    /// provisions a new sealed sector and reports the corresponding access
    fn new_sealed_sector_access(&self) -> Result<String, SectorManagerErr>;

    /// provisions a new staging sector and reports the corresponding access
    fn new_staging_sector_access(&self) -> Result<String, SectorManagerErr>;

    /// reports the number of bytes written to an unsealed sector
    fn num_unsealed_bytes(&self, access: String) -> Result<u64, SectorManagerErr>;

    /// sets the number of bytes in an unsealed sector identified by `access`
    fn truncate_unsealed(&self, access: String, size: u64) -> Result<(), SectorManagerErr>;

    /// writes `data` to the staging sector identified by `access`, incrementally preprocessing `access`
    fn write_and_preprocess(&self, access: String, data: &[u8]) -> Result<u64, SectorManagerErr>;

    fn delete_staging_sector_access(&self, access: String) -> Result<(), SectorManagerErr>;

    fn read_raw(
        &self,
        access: String,
        start_offset: u64,
        numb_bytes: u64,
    ) -> Result<Vec<u8>, SectorManagerErr>;
}

pub trait SectorStore {
    fn opts(&self) -> &proofs_config::ConfigOpts;

    fn manager(&self) -> &SectorManager;
}
