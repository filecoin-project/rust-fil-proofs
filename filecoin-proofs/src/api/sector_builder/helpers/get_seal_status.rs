use api::sector_builder::errors::SectorBuilderErr;
use api::sector_builder::metadata::SealStatus;
use api::sector_builder::state::SealedState;
use api::sector_builder::state::StagedState;
use api::sector_builder::SectorId;
use error;
use std::sync::MutexGuard;

pub fn get_seal_status(
    staged_state: &MutexGuard<StagedState>,
    sealed_state: &MutexGuard<SealedState>,
    sector_id: SectorId,
) -> error::Result<SealStatus> {
    sealed_state
        .sectors
        .get(&sector_id)
        .map(|sealed_sector| SealStatus::Sealed(Box::new(sealed_sector.clone())))
        .or_else(|| {
            staged_state
                .sectors_accepting_data
                .get(&sector_id)
                .map(|_| SealStatus::Pending)
        })
        .or_else(|| {
            staged_state
                .sectors
                .get(&sector_id)
                .and_then(|staged_sector| {
                    staged_sector
                        .sealing_error
                        .clone()
                        .map(SealStatus::Failed)
                        .or(Some(SealStatus::Sealing))
                })
        })
        .ok_or_else(|| {
            let err = format!("no sector with id {} found", sector_id);
            SectorBuilderErr::Unrecoverable(err).into()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use api::sector_builder::metadata::{SealedSectorMetadata, StagedSectorMetadata};
    use api::sector_builder::state::SealedState;
    use api::sector_builder::state::SectorBuilderState;
    use api::sector_builder::state::StagedState;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::sync::Mutex;

    fn setup() -> Arc<SectorBuilderState> {
        let mut staged_sectors: HashMap<u64, StagedSectorMetadata> = Default::default();
        let mut sealed_sectors: HashMap<u64, SealedSectorMetadata> = Default::default();
        let mut sectors_accepting_data: HashSet<u64> = Default::default();

        staged_sectors.insert(
            2,
            StagedSectorMetadata {
                sector_id: 2,
                ..Default::default()
            },
        );

        sectors_accepting_data.insert(3);

        sealed_sectors.insert(
            4,
            SealedSectorMetadata {
                sector_id: 4,
                ..Default::default()
            },
        );

        Arc::new(SectorBuilderState {
            prover_id: Default::default(),
            staged: Mutex::new(StagedState {
                sector_id_nonce: 0,
                sectors: staged_sectors,
                sectors_accepting_data,
            }),
            sealed: Mutex::new(SealedState {
                sectors: sealed_sectors,
            }),
        })
    }

    #[test]
    fn test_alpha() {
        let state = setup();

        let sealed_state = state.sealed.lock().unwrap();
        let staged_state = state.staged.lock().unwrap();

        let result = get_seal_status(&staged_state, &sealed_state, 1);
        assert!(result.is_err());

        let result = get_seal_status(&staged_state, &sealed_state, 2).unwrap();
        match result {
            SealStatus::Sealing => (),
            _ => panic!("should have been SealStatus::Sealing"),
        }

        let result = get_seal_status(&staged_state, &sealed_state, 3).unwrap();
        match result {
            SealStatus::Pending => (),
            _ => panic!("should have been SealStatus::Pending"),
        }

        let result = get_seal_status(&staged_state, &sealed_state, 4).unwrap();
        match result {
            SealStatus::Sealed(_) => (),
            _ => panic!("should have been SealStatus::Sealed"),
        }
    }
}
