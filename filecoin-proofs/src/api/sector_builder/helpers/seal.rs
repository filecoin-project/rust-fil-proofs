use crate::api::internal::seal as seal_internal;
use crate::api::internal::SealOutput;
use crate::api::sector_builder::metadata::sector_id_as_bytes;
use crate::api::sector_builder::metadata::SealedSectorMetadata;
use crate::api::sector_builder::metadata::StagedSectorMetadata;
use crate::api::sector_builder::WrappedSectorStore;
use crate::error;
use std::path::PathBuf;
use std::sync::Arc;

pub fn seal(
    sector_store: &Arc<WrappedSectorStore>,
    prover_id: &[u8; 31],
    staged_sector: StagedSectorMetadata,
) -> error::Result<SealedSectorMetadata> {
    // Provision a new sealed sector access through the manager.
    let sealed_sector_access = sector_store
        .inner
        .manager()
        .new_sealed_sector_access()
        .map_err(failure::Error::from)?;

    // Run the FPS seal operation. This call will block for a long time, so make
    // sure you're not holding any locks.

    let SealOutput {
        comm_r,
        comm_d,
        comm_r_star,
        snark_proof,
    } = seal_internal(
        (*sector_store.inner).config(),
        &PathBuf::from(staged_sector.sector_access.clone()),
        &PathBuf::from(sealed_sector_access.clone()),
        prover_id,
        &sector_id_as_bytes(staged_sector.sector_id)?,
    )?;

    let newly_sealed_sector = SealedSectorMetadata {
        sector_id: staged_sector.sector_id,
        sector_access: sealed_sector_access,
        pieces: staged_sector.pieces,
        comm_r_star,
        comm_r,
        comm_d,
        snark_proof,
    };

    Ok(newly_sealed_sector)
}
