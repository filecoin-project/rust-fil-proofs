use api::sector_builder::errors::err_piecenotfound;
use api::sector_builder::errors::err_unrecov;
use api::sector_builder::helpers::add_piece::add_piece;
use api::sector_builder::helpers::get_seal_status::get_seal_status;
use api::sector_builder::helpers::get_sectors_ready_for_sealing::get_sectors_ready_for_sealing;
use api::sector_builder::helpers::snapshots::load_snapshot;
use api::sector_builder::helpers::snapshots::make_snapshot;
use api::sector_builder::helpers::snapshots::persist_snapshot;
use api::sector_builder::metadata::SealStatus;
use api::sector_builder::metadata::SealedSectorMetadata;
use api::sector_builder::sealer::SealerInput;
use api::sector_builder::state::SectorBuilderState;
use api::sector_builder::state::StagedState;
use api::sector_builder::SectorId;
use api::sector_builder::WrappedKeyValueStore;
use api::sector_builder::WrappedSectorStore;
use error::Result;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

const FATAL_NOLOAD: &str = "[SchedulerWorker#init_from_metadata] could not load snapshot";
const FATAL_NORECV: &str = "[SchedulerWorker#init_from_metadata] could not receive task";
const FATAL_NOSEND: &str = "[SchedulerWorker#init_from_metadata] could not send";
const FATAL_SECMAP: &str = "[SectorBuilderStateMgrgr#handle_seal_result] insert failed";
const FATAL_SNPSHT: &str = "[SectorBuilderStateMgr#handle_seal_result] could not snapshot";
const FATAL_SLRSND: &str = "[SectorBuilderStateMgr#check_and_schedule] could not send to sealer";
const FATAL_HUNGUP: &str = "[SectorBuilderStateMgr#retrieve_piece] could not send to ret channel";

pub struct SchedulerWorker {
    pub thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug)]
pub enum SchedulerInput {
    AddPiece(String, Vec<u8>, mpsc::SyncSender<Result<SectorId>>),
    GetSealedSectors(mpsc::SyncSender<Result<Vec<SealedSectorMetadata>>>),
    GetSealStatus(SectorId, mpsc::SyncSender<Result<SealStatus>>),
    RetrievePiece(String, mpsc::SyncSender<Result<Vec<u8>>>),
    SealAllStagedSectors(mpsc::SyncSender<Result<()>>),
    GetMaxUserBytesPerStagedSector(mpsc::SyncSender<u64>),
    HandleSealResult(SectorId, Box<Result<SealedSectorMetadata>>),
    Shutdown,
}

impl SchedulerWorker {
    pub fn init_from_metadata(
        scheduler_input_rx: mpsc::Receiver<SchedulerInput>,
        scheduler_input_tx: mpsc::SyncSender<SchedulerInput>,
        sealer_input_tx: mpsc::Sender<SealerInput>,
        kv_store: Arc<WrappedKeyValueStore>,
        sector_store: Arc<WrappedSectorStore>,
        last_committed_sector_id: SectorId,
        max_num_staged_sectors: u8,
        prover_id: [u8; 31],
    ) -> SchedulerWorker {
        let thread = thread::spawn(move || {
            // Build the scheduler's initial state. If available, we
            // reconstitute this state from persisted metadata. If not, we
            // create it from scratch.
            let state = {
                let loaded = load_snapshot(&kv_store, &prover_id)
                    .expect(FATAL_NOLOAD)
                    .map(|x| x.into());

                loaded.unwrap_or_else(|| SectorBuilderState {
                    prover_id,
                    staged: StagedState {
                        sector_id_nonce: last_committed_sector_id,
                        sectors: Default::default(),
                        sectors_accepting_data: Default::default(),
                    },
                    sealed: Default::default(),
                })
            };

            let max_user_bytes_per_staged_sector =
                sector_store.inner.config().max_unsealed_bytes_per_sector();

            let mut m = SectorBuilderStateManager {
                kv_store,
                sector_store,
                state,
                sealer_input_tx,
                scheduler_input_tx: scheduler_input_tx.clone(),
                max_num_staged_sectors,
                max_user_bytes_per_staged_sector,
            };

            loop {
                let task = scheduler_input_rx.recv().expect(FATAL_NORECV);

                // Dispatch to the appropriate task-handler.
                match task {
                    SchedulerInput::AddPiece(key, bytes, tx) => {
                        tx.send(m.add_piece(key, &bytes)).expect(FATAL_NOSEND);
                    }
                    SchedulerInput::GetSealStatus(sector_id, tx) => {
                        tx.send(m.get_seal_status(sector_id)).expect(FATAL_NOSEND);
                    }
                    SchedulerInput::RetrievePiece(piece_key, tx) => m.retrieve_piece(piece_key, tx),
                    SchedulerInput::GetSealedSectors(tx) => {
                        tx.send(m.get_sealed_sectors()).expect(FATAL_NOSEND);
                    }
                    SchedulerInput::GetMaxUserBytesPerStagedSector(tx) => {
                        tx.send(m.max_user_bytes()).expect(FATAL_NOSEND);
                    }
                    SchedulerInput::SealAllStagedSectors(tx) => {
                        tx.send(m.seal_all_staged_sectors()).expect(FATAL_NOSEND);
                    }
                    SchedulerInput::HandleSealResult(sector_id, result) => {
                        m.handle_seal_result(sector_id, *result);
                    }
                    SchedulerInput::Shutdown => break,
                }
            }
        });

        SchedulerWorker {
            thread: Some(thread),
        }
    }
}

// The SectorBuilderStateManager is the owner of all sector-related metadata.
// It dispatches expensive operations (e.g. unseal and seal) to the sealer
// worker-threads. Other, inexpensive work (or work which needs to be performed
// serially) is handled by the SectorBuilderStateManager itself.
pub struct SectorBuilderStateManager {
    kv_store: Arc<WrappedKeyValueStore>,
    sector_store: Arc<WrappedSectorStore>,
    state: SectorBuilderState,
    sealer_input_tx: mpsc::Sender<SealerInput>,
    scheduler_input_tx: mpsc::SyncSender<SchedulerInput>,
    max_num_staged_sectors: u8,
    max_user_bytes_per_staged_sector: u64,
}

impl SectorBuilderStateManager {
    // Unseals the sector containing the referenced piece and returns its
    // bytes. Produces an error if this sector builder does not have a sealed
    // sector containing the referenced piece.
    pub fn retrieve_piece(
        &self,
        piece_key: String,
        return_channel: mpsc::SyncSender<Result<Vec<u8>>>,
    ) {
        let opt_sealed_sector = self.state.sealed.sectors.values().find(|sector| {
            sector
                .pieces
                .iter()
                .any(|piece| piece.piece_key == piece_key)
        });

        if let Some(sealed_sector) = opt_sealed_sector {
            let sealed_sector = Box::new(sealed_sector.clone());
            let task = SealerInput::Unseal(piece_key, sealed_sector, return_channel);

            self.sealer_input_tx.clone().send(task).expect(FATAL_SLRSND);
        } else {
            return_channel
                .send(Err(err_piecenotfound(piece_key.to_string()).into()))
                .expect(FATAL_HUNGUP);
        }
    }

    // Returns sealing status for the sector with specified id. If no sealed or
    // staged sector exists with the provided id, produce an error.
    pub fn get_seal_status(&self, sector_id: SectorId) -> Result<SealStatus> {
        get_seal_status(&self.state.staged, &self.state.sealed, sector_id)
    }

    // Write the piece to storage, obtaining the sector id with which the
    // piece-bytes are now associated.
    pub fn add_piece(&mut self, piece_key: String, piece_bytes: &[u8]) -> Result<u64> {
        let destination_sector_id = add_piece(
            &self.sector_store,
            &mut self.state.staged,
            piece_key,
            piece_bytes,
        )?;

        self.check_and_schedule(false)?;
        self.checkpoint()?;

        Ok(destination_sector_id)
    }

    // For demo purposes. Schedules sealing of all staged sectors.
    pub fn seal_all_staged_sectors(&mut self) -> Result<()> {
        self.check_and_schedule(true)?;
        self.checkpoint()
    }

    // Produces a vector containing metadata for all sealed sectors that this
    // SectorBuilder knows about.
    pub fn get_sealed_sectors(&self) -> Result<Vec<SealedSectorMetadata>> {
        Ok(self.state.sealed.sectors.values().cloned().collect())
    }

    // Returns the number of user-provided bytes that will fit into a staged
    // sector.
    pub fn max_user_bytes(&self) -> u64 {
        self.max_user_bytes_per_staged_sector
    }

    // Update metadata to reflect the sealing results.
    pub fn handle_seal_result(
        &mut self,
        sector_id: SectorId,
        result: Result<SealedSectorMetadata>,
    ) {
        // scope exists to end the mutable borrow of self so that we can
        // checkpoint
        {
            let staged_state = &mut self.state.staged;
            let sealed_state = &mut self.state.sealed;

            if result.is_err() {
                if let Some(staged_sector) = staged_state.sectors.get_mut(&sector_id) {
                    staged_sector.sealing_error =
                        Some(format!("{}", err_unrecov(result.unwrap_err())));
                };
            } else {
                // Remove the staged sector from the state map.
                let _ = staged_state.sectors.remove(&sector_id);

                // Insert the newly-sealed sector into the other state map.
                let sealed_sector = result.expect(FATAL_SECMAP);

                sealed_state.sectors.insert(sector_id, sealed_sector);
            }
        }

        self.checkpoint().expect(FATAL_SNPSHT);
    }

    // Check for sectors which should no longer receive new user piece-bytes and
    // schedule them for sealing.
    fn check_and_schedule(&mut self, seal_all_staged_sectors: bool) -> Result<()> {
        let staged_state = &mut self.state.staged;

        let to_be_sealed = get_sectors_ready_for_sealing(
            staged_state,
            self.max_user_bytes_per_staged_sector,
            self.max_num_staged_sectors,
            seal_all_staged_sectors,
        );

        // Mark the to-be-sealed sectors as no longer accepting data.
        for sector in to_be_sealed.iter() {
            let _ = staged_state
                .sectors_accepting_data
                .remove(&sector.sector_id);
        }

        // Fire-and-forget seal-scheduling.
        for sector in to_be_sealed {
            self.sealer_input_tx
                .clone()
                .send(SealerInput::Seal(
                    sector.clone(),
                    self.scheduler_input_tx.clone(),
                ))
                .expect(FATAL_SLRSND);
        }

        Ok(())
    }

    // Create and persist metadata snapshot.
    fn checkpoint(&self) -> Result<()> {
        let snapshot = make_snapshot(
            &self.state.prover_id,
            &self.state.staged,
            &self.state.sealed,
        );
        persist_snapshot(&self.kv_store, &snapshot)?;

        Ok(())
    }
}
