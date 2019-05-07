use crate::api::internal;
use crate::api::sector_builder::errors::err_unrecov;
use crate::api::sector_builder::metadata::sector_id_as_bytes;
use crate::api::sector_builder::metadata::SealedSectorMetadata;
use crate::api::sector_builder::WrappedSectorStore;
use crate::api::sector_builder::pieces::{get_piece_start, get_piece_by_key};
use crate::error;
use sector_base::api::bytes_amount::UnpaddedBytesAmount;
use std::path::PathBuf;
use std::sync::Arc;

// Unseals and returns the piece-bytes for the first sector found containing
// a piece with matching key.
pub fn retrieve_piece<'a>(
    sector_store: &Arc<WrappedSectorStore>,
    sealed_sector: &SealedSectorMetadata,
    prover_id: &[u8; 31],
    piece_key: &'a str,
) -> error::Result<Vec<u8>> {
    let staging_sector_access = sector_store
        .inner
        .manager()
        .new_staging_sector_access()
        .map_err(failure::Error::from)?;

    let result = retrieve_piece_aux(
        sector_store,
        sealed_sector,
        prover_id,
        piece_key,
        &staging_sector_access,
    );

    if result.is_ok() {
        sector_store
            .inner
            .manager()
            .delete_staging_sector_access(&staging_sector_access)?;
    }

    let (_, bytes) = result?;

    Ok(bytes)
}

fn retrieve_piece_aux<'a>(
    sector_store: &Arc<WrappedSectorStore>,
    sealed_sector: &SealedSectorMetadata,
    prover_id: &[u8; 31],
    piece_key: &'a str,
    staging_sector_access: &'a str,
) -> error::Result<(UnpaddedBytesAmount, Vec<u8>)> {
    let piece = get_piece_by_key(&sealed_sector.pieces, piece_key).ok_or_else(|| {
        let msg = format!(
            "piece {} not found in sector {}",
            piece_key, &sealed_sector.sector_id
        );
        err_unrecov(msg)
    })?;
    let start_offset = get_piece_start(&sealed_sector.pieces, piece);

    let num_bytes_unsealed = internal::get_unsealed_range(
        (*sector_store.inner).proofs_config().porep_config(),
        &PathBuf::from(sealed_sector.sector_access.clone()),
        &PathBuf::from(staging_sector_access),
        prover_id,
        &sector_id_as_bytes(sealed_sector.sector_id)?,
        start_offset,
        piece.num_bytes,
    )?;

    if num_bytes_unsealed != piece.num_bytes {
        let s = format!(
            "expected to unseal {} bytes, but unsealed {} bytes",
            u64::from(piece.num_bytes),
            u64::from(num_bytes_unsealed)
        );

        return Err(err_unrecov(s).into());
    }

    let piece_bytes = sector_store.inner.manager().read_raw(
        &staging_sector_access.to_string(),
        0,
        num_bytes_unsealed,
    )?;

    Ok((num_bytes_unsealed, piece_bytes))
}
