use api::sector_builder::metadata::StagedSectorMetadata;
use api::sector_builder::state::StagedState;
use api::sector_builder::MAX_NUM_STAGED_SECTORS;
use error;
use std::cmp::Reverse;
use std::sync::MutexGuard;

pub fn get_sectors_ready_for_sealing(
    staged_state: &MutexGuard<StagedState>,
    seal_all_staged_sectors: bool,
) -> error::Result<Vec<StagedSectorMetadata>> {
    // Get a vector of owned (cloned) staged sectors with the most recently
    // provisioned (by sector id) at the head. This vector will have a size in
    // the range [1, MAX_NUM_STAGED_SECTORS+1].
    let newest_first = {
        let mut xs = staged_state
            .sectors
            .values()
            .filter(|x| staged_state.sectors_accepting_data.contains(&x.sector_id))
            .cloned()
            .collect::<Vec<StagedSectorMetadata>>();

        xs.sort_unstable_by_key(|x| Reverse(x.sector_id));

        xs
    };

    let to_seal = newest_first.into_iter().skip(if seal_all_staged_sectors {
        0
    } else {
        MAX_NUM_STAGED_SECTORS
    });

    Ok(to_seal.collect::<Vec<StagedSectorMetadata>>())
}
