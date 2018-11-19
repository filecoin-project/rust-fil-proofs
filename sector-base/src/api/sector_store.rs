use api::errors::SectorManagerErr;

pub trait SectorConfig {
    /// if true, uses something other exact bits, correct parameters, or full proofs
    fn is_fake(&self) -> bool;

    /// if provided, an artificial delay to seal
    fn simulate_delay_seconds(&self) -> Option<u32>;

    /// returns the number of bytes that will fit into a sector managed by this store
    fn max_unsealed_bytes_per_sector(&self) -> u64;

    /// returns the number of bytes in a sealed sector managed by this store
    fn sector_bytes(&self) -> u64;

    /// We need a distinguished place to cache 'the' parameters corresponding to the SetupParams
    /// currently being used. These are only easily generated at replication time but need to be
    /// accessed at verification time too.
    fn dummy_parameter_cache_name(&self) -> String;
}

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

    fn read_raw(
        &self,
        access: String,
        start_offset: u64,
        numb_bytes: u64,
    ) -> Result<Vec<u8>, SectorManagerErr>;
}

pub trait SectorStore {
    fn config(&self) -> &SectorConfig;
    fn manager(&self) -> &SectorManager;
}
