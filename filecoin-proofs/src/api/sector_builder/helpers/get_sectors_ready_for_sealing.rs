use api::sector_builder::metadata::sum_piece_bytes;
use api::sector_builder::metadata::StagedSectorMetadata;
use api::sector_builder::state::StagedState;
use itertools::chain;
use std::cmp::Reverse;
use std::sync::MutexGuard;

pub fn get_sectors_ready_for_sealing(
    staged_state: &MutexGuard<StagedState>,
    max_user_bytes_per_staged_sector: u64,
    max_num_staged_sectors: u8,
    seal_all_staged_sectors: bool,
) -> Vec<StagedSectorMetadata> {
    let (full, mut not_full): (Vec<&StagedSectorMetadata>, Vec<&StagedSectorMetadata>) =
        staged_state
            .sectors
            .values()
            .filter(|x| staged_state.sectors_accepting_data.contains(&x.sector_id))
            .partition(|x| max_user_bytes_per_staged_sector <= sum_piece_bytes(x));

    not_full.sort_unstable_by_key(|x| Reverse(x.sector_id));

    let num_to_skip = if seal_all_staged_sectors {
        0
    } else {
        max_num_staged_sectors as usize
    };

    chain(full.into_iter(), not_full.into_iter().skip(num_to_skip))
        .cloned()
        .collect::<Vec<StagedSectorMetadata>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use api::sector_builder::metadata::Piece;
    use api::sector_builder::metadata::StagedSectorMetadata;
    use api::sector_builder::state::StagedState;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    fn make_meta(m: &mut HashMap<u64, StagedSectorMetadata>, sector_id: u64, num_bytes: u64) {
        m.insert(
            sector_id,
            StagedSectorMetadata {
                sector_id,
                pieces: vec![Piece {
                    piece_key: format!("{}", sector_id),
                    num_bytes,
                }],
                ..Default::default()
            },
        );
    }

    #[test]
    fn test_seals_all() {
        let mut m: HashMap<u64, StagedSectorMetadata> = HashMap::new();

        make_meta(&mut m, 200, 0);
        make_meta(&mut m, 201, 0);

        let q = m.keys().cloned().collect::<HashSet<u64>>();

        let state = Mutex::new(StagedState {
            sector_id_nonce: 100,
            sectors: m,
            sectors_accepting_data: q,
        });

        let to_seal: Vec<u64> =
            get_sectors_ready_for_sealing(&state.lock().unwrap(), 127, 10, true)
                .into_iter()
                .map(|x| x.sector_id)
                .collect();

        assert_eq!(vec![201 as u64, 200 as u64], to_seal);
    }

    #[test]
    fn test_seals_full() {
        let mut m: HashMap<u64, StagedSectorMetadata> = HashMap::new();

        make_meta(&mut m, 200, 127);
        make_meta(&mut m, 201, 0);

        let q = m.keys().cloned().collect::<HashSet<u64>>();

        let state = Mutex::new(StagedState {
            sector_id_nonce: 100,
            sectors: m,
            sectors_accepting_data: q,
        });

        let to_seal: Vec<u64> =
            get_sectors_ready_for_sealing(&state.lock().unwrap(), 127, 10, false)
                .into_iter()
                .map(|x| x.sector_id)
                .collect();

        assert_eq!(vec![200 as u64], to_seal);
    }

    #[test]
    fn test_seals_excess() {
        let mut m: HashMap<u64, StagedSectorMetadata> = HashMap::new();

        make_meta(&mut m, 200, 0);
        make_meta(&mut m, 201, 0);
        make_meta(&mut m, 202, 0);
        make_meta(&mut m, 203, 0);

        let q = m.keys().cloned().collect::<HashSet<u64>>();

        let state = Mutex::new(StagedState {
            sector_id_nonce: 100,
            sectors: m,
            sectors_accepting_data: q,
        });

        let to_seal: Vec<u64> =
            get_sectors_ready_for_sealing(&state.lock().unwrap(), 127, 2, false)
                .into_iter()
                .map(|x| x.sector_id)
                .collect();

        assert_eq!(vec![201 as u64, 200 as u64], to_seal);
    }

    #[test]
    fn test_noop() {
        let mut m: HashMap<u64, StagedSectorMetadata> = HashMap::new();

        make_meta(&mut m, 200, 0);
        make_meta(&mut m, 201, 0);
        make_meta(&mut m, 202, 0);
        make_meta(&mut m, 203, 0);

        let q = m.keys().cloned().collect::<HashSet<u64>>();

        let state = Mutex::new(StagedState {
            sector_id_nonce: 100,
            sectors: m,
            sectors_accepting_data: q,
        });

        let to_seal: Vec<u64> =
            get_sectors_ready_for_sealing(&state.lock().unwrap(), 127, 4, false)
                .into_iter()
                .map(|x| x.sector_id)
                .collect();

        assert_eq!(vec![0; 0], to_seal);
    }

    #[test]
    fn test_noop_all_being_sealed() {
        let mut m: HashMap<u64, StagedSectorMetadata> = HashMap::new();

        make_meta(&mut m, 200, 127);
        make_meta(&mut m, 201, 127);
        make_meta(&mut m, 202, 127);
        make_meta(&mut m, 203, 127);

        let state = Mutex::new(StagedState {
            sector_id_nonce: 100,
            sectors: m,
            sectors_accepting_data: HashSet::new(),
        });

        let to_seal: Vec<u64> =
            get_sectors_ready_for_sealing(&state.lock().unwrap(), 127, 4, false)
                .into_iter()
                .map(|x| x.sector_id)
                .collect();

        assert_eq!(vec![0; 0], to_seal);
    }
}
