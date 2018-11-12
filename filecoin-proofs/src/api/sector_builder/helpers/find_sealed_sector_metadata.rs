use api::sector_builder::errors::err_unrecov;
use api::sector_builder::metadata::SealedSectorMetadata;
use api::sector_builder::state::SectorBuilderState;
use api::sector_builder::SectorId;
use error;
use std::sync::Arc;

pub fn find_sealed_sector_metadata(
    state: &Arc<SectorBuilderState>,
    sector_id: SectorId,
) -> error::Result<Option<SealedSectorMetadata>> {
    state
        .sealed
        .lock()
        .map(|state| state.sectors.get(&sector_id).map(|s| (*s).clone()))
        .map_err(|err| -> failure::Error { err_unrecov(err).into() })
}
