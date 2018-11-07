use api::disk_backed_storage::{new_sector_store, ConfiguredStore};
use api::errors::*;
use api::sector_store::SectorStore;
use error::Result;
use failure::Error;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

type SectorId = u64;

#[derive(Debug, Clone)]
pub struct StagedSectorMetadata {
    pub sector_id: SectorId,
    pub sector_access: String,
    pub pieces: Vec<PieceMetadata>,
}

#[derive(Debug, Clone)]
pub struct PieceMetadata {
    pub key: String,
    pub num_bytes: u64,
}

#[derive(Debug, Default)]
pub struct StagedState {
    staged_sectors: HashMap<SectorId, StagedSectorMetadata>,
    sectors_accepting_data: HashSet<SectorId>,
}

pub struct SectorBuilder {
    metadata_dir: String,
    prover_id: [u8; 31],
    sector_id_nonce: Mutex<u64>,
    sector_store: Box<SectorStore>,

    staged_state: Arc<Mutex<StagedState>>,
}

impl SectorBuilder {
    // Initialize and return a SectorBuilder from metadata persisted to disk if
    // it exists. Otherwise, initialize and return a fresh SectorBuilder. The
    // metadata key is equal to the prover_id.
    //
    // TODO: As of now, this function will always return a new SectorBuilder. A
    // real metadata store is forthcoming.
    pub fn init_from_metadata<S: Into<String>>(
        sector_store_config: &ConfiguredStore,
        last_used_sector_id: u64,
        metadata_dir: S,
        prover_id: [u8; 31],
        sealed_sector_dir: S,
        staged_sector_dir: S,
    ) -> Result<SectorBuilder> {
        let sector_store = Box::new(new_sector_store(
            sector_store_config,
            sealed_sector_dir.into(),
            staged_sector_dir.into(),
        ));

        Ok(SectorBuilder {
            metadata_dir: metadata_dir.into(),
            prover_id,
            sector_id_nonce: Mutex::new(last_used_sector_id),
            sector_store,
            staged_state: Default::default(),
        })
    }

    // Returns the number of user-provided bytes that will fit into a staged sector.
    pub fn get_max_user_bytes_per_staged_sector(&self) -> u64 {
        self.sector_store.config().max_unsealed_bytes_per_sector()
    }

    // Atomically increment the nonce and return its incremented value. This
    // function has the side-effect of mutating the mutex-protected nonce.
    fn get_next_sector_id(&self) -> u64 {
        let mut n = self.sector_id_nonce.lock().unwrap();
        *n += 1;
        *n
    }

    // Given a list of staged sectors which are accepting data, return the
    // first staged sector into which the bytes will fit.
    fn compute_destination_sector_id(
        candidate_sectors: &[StagedSectorMetadata],
        max_bytes_per_sector: u64,
        num_bytes_in_piece: u64,
    ) -> Result<Option<u64>> {
        if num_bytes_in_piece > max_bytes_per_sector {
            Err(SectorBuilderErr::OverflowError {
                num_bytes_in_piece,
                max_bytes_per_sector,
            }
            .into())
        } else {
            Ok(candidate_sectors
                .iter()
                .find(move |staged_sector| {
                    let num_bytes_in_sector: u64 =
                        staged_sector.pieces.iter().map(|x| x.num_bytes).sum();

                    (max_bytes_per_sector - num_bytes_in_sector) > num_bytes_in_piece
                })
                .map(|x| x.sector_id))
        }
    }

    // Provisions a new staged sector and returns its sector_id. Callers must
    // hold the lock.
    fn provision_new_staged_sector<'a>(
        &self,
        locked_state: &mut MutexGuard<'a, StagedState>,
    ) -> Result<u64> {
        let mgr = self.sector_store.manager();
        let sector_id = self.get_next_sector_id();

        let access = mgr.new_staging_sector_access()?;

        let meta = StagedSectorMetadata {
            sector_id,
            sector_access: access.clone(),
            pieces: Default::default(),
        };

        locked_state.sectors_accepting_data.insert(meta.sector_id);
        locked_state
            .staged_sectors
            .insert(meta.sector_id, meta.clone());

        Ok(sector_id)
    }

    pub fn add_piece<S: Into<String>>(&self, piece_key: S, piece_bytes: &[u8]) -> Result<u64> {
        let mutex = self.staged_state.clone();
        let mut staged_state = mutex.lock().unwrap();

        let sectors_accepting_data: Vec<StagedSectorMetadata> = staged_state
            .staged_sectors
            .iter()
            .filter(|(k, _)| staged_state.sectors_accepting_data.contains(k))
            .map(|(_, v)| (*v).clone())
            .collect();

        let opt_dest_sector_id = SectorBuilder::compute_destination_sector_id(
            &sectors_accepting_data[..],
            self.sector_store.config().max_unsealed_bytes_per_sector(),
            piece_bytes.len() as u64,
        )?;

        let dest_sector_id = opt_dest_sector_id
            .ok_or(())
            .or_else(|_| self.provision_new_staged_sector(&mut staged_state))?;

        if let Some(s) = staged_state.staged_sectors.get_mut(&dest_sector_id) {
            self.sector_store
                .manager()
                .write_and_preprocess(s.sector_access.clone(), &piece_bytes)
                .map_err(|err| err.into())
                .and_then(|num_bytes_written| {
                    if num_bytes_written != piece_bytes.len() as u64 {
                        Err(SectorBuilderErr::IncompleteWriteError {
                            num_bytes_written,
                            num_bytes_in_piece: piece_bytes.len() as u64,
                        }
                        .into())
                    } else {
                        Ok(s.sector_id)
                    }
                })
                .map(|sector_id| {
                    s.pieces.push(PieceMetadata {
                        key: piece_key.into(),
                        num_bytes: piece_bytes.len() as u64,
                    });

                    sector_id
                })
        } else {
            Err(SectorBuilderErr::InvalidInternalStateError(
                "unable to retrieve sector from state-map".to_string(),
            )
            .into())
        }
    }
}
