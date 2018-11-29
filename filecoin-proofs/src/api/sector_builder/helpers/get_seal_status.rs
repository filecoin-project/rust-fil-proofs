use api::sector_builder::errors::SectorBuilderErr;
use api::sector_builder::metadata::SealStatus;
use api::sector_builder::state::SealedState;
use api::sector_builder::state::StagedState;
use api::sector_builder::SectorId;
use error;

pub fn get_seal_status(
    staged_state: &StagedState,
    sealed_state: &SealedState,
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

    fn setup() -> SectorBuilderState {
        let mut staged_sectors: HashMap<SectorId, StagedSectorMetadata> = Default::default();
        let mut sealed_sectors: HashMap<SectorId, SealedSectorMetadata> = Default::default();
        let mut sectors_accepting_data: HashSet<SectorId> = Default::default();

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

        SectorBuilderState {
            prover_id: Default::default(),
            staged: StagedState {
                sector_id_nonce: 0,
                sectors: staged_sectors,
                sectors_accepting_data,
            },
            sealed: SealedState {
                sectors: sealed_sectors,
            },
        }
    }

    #[test]
    fn test_alpha() {
        let state = setup();

        let sealed_state = state.sealed;
        let staged_state = state.staged;

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
