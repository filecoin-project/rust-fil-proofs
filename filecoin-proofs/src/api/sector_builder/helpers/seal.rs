use api::internal::seal as seal_internal;
use api::sector_builder::errors::err_unrecov;
use api::sector_builder::metadata::SealedSectorMetadata;
use api::sector_builder::state::SectorBuilderState;
use api::sector_builder::SectorId;
use byteorder::LittleEndian;
use byteorder::WriteBytesExt;
use error;
use sector_base::api::disk_backed_storage::ConcreteSectorStore;
use sector_base::api::sector_store::SectorStore;
use std::path::PathBuf;
use std::sync::Arc;

pub fn seal(
    sector_store: &Arc<ConcreteSectorStore>,
    state: &Arc<SectorBuilderState>,
    sector_id: SectorId,
) -> error::Result<SealedSectorMetadata> {
    let sealing_result = seal_aux(sector_store, state, sector_id);

    // Update staged sector metadata, adding the error encountered while
    // sealing.
    if let Err(ref err) = sealing_result {
        let _ = state
            .staged
            .lock()
            .unwrap()
            .sectors
            .get_mut(&sector_id)
            .map(|staged_sector| {
                staged_sector.sealing_error = Some(format!("{}", err_unrecov(err)));
            });
    }

    sealing_result
}

fn seal_aux(
    sector_store: &Arc<ConcreteSectorStore>,
    state: &Arc<SectorBuilderState>,
    sector_id: SectorId,
) -> error::Result<SealedSectorMetadata> {
    // Get the sector to be sealed from our state-map, acquiring and releasing
    // the lock within the block.
    let to_be_sealed = {
        state
            .staged
            .lock()
            .unwrap()
            .sectors
            .get(&sector_id)
            .ok_or_else(|| {
                err_unrecov(format!("staged sector-map didn't contain id {}", sector_id))
            })?
            .clone()
    };

    // Provision a new sealed sector access through the manager.
    let sealed_sector_access = sector_store
        .manager()
        .new_sealed_sector_access()
        .map_err(failure::Error::from)?;

    // Transmute a u64 sector id to a zero-padded byte array.
    // TODO: Is LittleEndian what we want here?
    let mut sector_id_as_bytes = [0u8; 31];
    sector_id_as_bytes
        .as_mut()
        .write_u64::<LittleEndian>(sector_id)?;

    // Run the FPS seal operation. This call will block for a long time, so make
    // sure you're not holding any locks.
    let (comm_r, comm_d, comm_r_star, snark_proof) = seal_internal(
        &(**sector_store),
        &PathBuf::from(to_be_sealed.sector_access.clone()),
        &PathBuf::from(sealed_sector_access.clone()),
        state.prover_id,
        sector_id_as_bytes,
    )?;

    let newly_sealed_sector = SealedSectorMetadata {
        sector_id: to_be_sealed.sector_id,
        sector_access: sealed_sector_access,
        pieces: to_be_sealed.pieces,
        comm_r_star,
        comm_r,
        comm_d,
        snark_proof,
    };

    // Remove the sector from the staged state-map after sealing and add it
    // to the sealed sector state-map.
    {
        let mut staged_state = state.staged.lock().unwrap();
        let mut sealed_state = state.sealed.lock().unwrap();

        let _ = staged_state.sectors.remove(&sector_id);

        sealed_state
            .sectors
            .insert(sector_id, newly_sealed_sector.clone());
    }

    Ok(newly_sealed_sector)
}
