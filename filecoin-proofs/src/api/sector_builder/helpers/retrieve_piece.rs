use crate::api::internal;
use crate::api::sector_builder::errors::err_unrecov;
use crate::api::sector_builder::metadata::sector_id_as_bytes;
use crate::api::sector_builder::metadata::SealedSectorMetadata;
use crate::api::sector_builder::WrappedSectorStore;
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
    let (start_offset, num_bytes) = piece_pos(&sealed_sector, piece_key).ok_or_else(|| {
        let msg = format!(
            "piece {} not found in sector {}",
            piece_key, &sealed_sector.sector_id
        );
        err_unrecov(msg)
    })?;

    let num_bytes_unsealed = internal::get_unsealed_range(
        (*sector_store.inner).config(),
        &PathBuf::from(sealed_sector.sector_access.clone()),
        &PathBuf::from(staging_sector_access),
        prover_id,
        &sector_id_as_bytes(sealed_sector.sector_id)?,
        start_offset,
        num_bytes,
    )?;

    if num_bytes_unsealed != num_bytes {
        let s = format!(
            "expected to unseal {} bytes, but unsealed {} bytes",
            u64::from(num_bytes),
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

// Returns a tuple of piece bytes-offset and number-of-bytes in piece if the
// provided sealed sector contains a matching piece.
fn piece_pos(
    sealed_sector: &SealedSectorMetadata,
    piece_key: &str,
) -> Option<(u64, UnpaddedBytesAmount)> {
    let (found_piece, start_offset, num_bytes) = sealed_sector.pieces.iter().fold(
        (false, 0, UnpaddedBytesAmount(0)),
        |(eject, start_offset, num_bytes), item| {
            if eject {
                (eject, start_offset, num_bytes)
            } else if item.piece_key == piece_key {
                (true, start_offset, item.num_bytes)
            } else {
                (
                    false,
                    start_offset + u64::from(item.num_bytes),
                    item.num_bytes,
                )
            }
        },
    );

    if found_piece {
        Some((start_offset, num_bytes))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::sector_builder::metadata::PieceMetadata;

    #[test]
    fn test_alpha() {
        let mut sealed_sector: SealedSectorMetadata = Default::default();

        sealed_sector.pieces.push(PieceMetadata {
            piece_key: String::from("x"),
            num_bytes: UnpaddedBytesAmount(5),
        });

        sealed_sector.pieces.push(PieceMetadata {
            piece_key: String::from("y"),
            num_bytes: UnpaddedBytesAmount(30),
        });

        sealed_sector.pieces.push(PieceMetadata {
            piece_key: String::from("z"),
            num_bytes: UnpaddedBytesAmount(100),
        });

        match piece_pos(&sealed_sector, "x") {
            Some(pair) => assert_eq!(pair, (0, UnpaddedBytesAmount(5))),
            None => panic!(),
        }

        match piece_pos(&sealed_sector, "y") {
            Some(pair) => assert_eq!(pair, (5, UnpaddedBytesAmount(30))),
            None => panic!(),
        }

        match piece_pos(&sealed_sector, "z") {
            Some(pair) => assert_eq!(pair, (35, UnpaddedBytesAmount(100))),
            None => panic!(),
        }
    }
}
