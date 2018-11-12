use api::sector_builder::helpers::add_piece::*;
use api::sector_builder::helpers::find_sealed_sector_metadata::*;
use api::sector_builder::helpers::get_sectors_ready_for_sealing::*;
use api::sector_builder::metadata::*;
use api::sector_builder::state::*;
use api::sector_builder::worker::*;
use error::Result;
use sector_base::api::disk_backed_storage::new_sector_store;
use sector_base::api::disk_backed_storage::ConcreteSectorStore;
use sector_base::api::disk_backed_storage::SBConfiguredStore;
use sector_base::api::sector_store::SectorStore;
use std::sync::{mpsc, Arc, Mutex};

pub mod errors;
mod helpers;
mod metadata;
mod state;
mod worker;

const MAX_NUM_STAGED_SECTORS: usize = 2;
const NUM_SEAL_WORKERS: usize = 2;

pub type SectorId = u64;

pub struct SectorBuilder {
    // Provides thread-safe access to a SectorStore.
    //
    // TODO: Non-boxed trait objects, have a size which is unknown at compile
    // time. A reference, e.g. &SectorStore does have a known size, but is not
    // thread safe w/out an Arc. For now, the SectorBuilder owns the concrete
    // type, which we can retrieve from an Arc and transmute to a &SectorStore
    // value for the internal::seal function. In the future (soon), we need to
    // figure out if the internal::seal API needs to change or if there's some
    // other way to allow thread-safe access to a shared SectorStore.
    sector_store: Arc<ConcreteSectorStore>,

    // A reference-counted struct which holds all SectorBuilder state. Mutable
    // fields are Mutex-guarded.
    state: Arc<SectorBuilderState>,

    // A work queue which should only be sent Task::Seal. Prevents FFI consumers
    // from queueing behind long-running seal operations.
    seal_tx: mpsc::Sender<Task>,

    // For additional seal concurrency, add more workers here.
    seal_workers: Vec<Worker>,
}

impl SectorBuilder {
    // Initialize and return a SectorBuilder from metadata persisted to disk if
    // it exists. Otherwise, initialize and return a fresh SectorBuilder. The
    // metadata key is equal to the prover_id.
    //
    // TODO: As of now, this function will always return a new SectorBuilder. A
    // real metadata store is forthcoming.
    pub fn init_from_metadata<S: Into<String>>(
        sector_store_config: &SBConfiguredStore,
        last_used_sector_id: u64,
        metadata_dir: S,
        prover_id: [u8; 31],
        sealed_sector_dir: S,
        staged_sector_dir: S,
    ) -> Result<SectorBuilder> {
        // Build the SectorBuilder's initial state. If available, we
        // reconstitute this stage from persistence. If not, we create it from
        // scratch.
        let state = Arc::new(SectorBuilderState {
            _metadata_dir: metadata_dir.into(),
            prover_id,
            staged: Mutex::new(StagedState {
                sector_id_nonce: last_used_sector_id,
                sectors: Default::default(),
                sectors_accepting_data: Default::default(),
            }),
            sealed: Default::default(),
        });

        // Initialize a SectorStore and wrap it in an Arc so we can access it
        // from multiple threads. Our implementation assumes that the
        // SectorStore is safe for concurrent access.
        let sector_store: Arc<ConcreteSectorStore> = Arc::new(new_sector_store(
            sector_store_config,
            sealed_sector_dir.into(),
            staged_sector_dir.into(),
        ));

        // Configure seal queue workers and channels.
        let (seal_tx, seal_workers) = {
            let (tx, rx) = mpsc::channel();
            let rx = Arc::new(Mutex::new(rx));

            let workers = (0..NUM_SEAL_WORKERS)
                .map(|n| {
                    Worker::new(
                        n,
                        Arc::clone(&rx),
                        Arc::clone(&sector_store),
                        Arc::clone(&state),
                    )
                })
                .collect();

            (tx, workers)
        };

        Ok(SectorBuilder {
            seal_tx,
            seal_workers,
            sector_store,
            state,
        })
    }

    // Returns the number of user-provided bytes that will fit into a staged
    // sector.
    pub fn get_max_user_bytes_per_staged_sector(&self) -> u64 {
        self.sector_store
            .clone()
            .config()
            .max_unsealed_bytes_per_sector()
    }

    // Stages user piece-bytes for sealing. Note that add_piece calls are
    // processed sequentially to make bin packing easier.
    pub fn add_piece<S: Into<String>>(&self, piece_key: S, piece_bytes: &[u8]) -> Result<SectorId> {
        let mut locked_staged_state = self.state.staged.lock().unwrap();

        // Write the piece to storage, obtaining the sector id with which the
        // piece-bytes are now associated.
        let destination_sector_id = add_piece(
            &self.sector_store,
            &mut locked_staged_state,
            piece_key,
            piece_bytes,
        )?;

        let to_be_sealed = get_sectors_ready_for_sealing(&locked_staged_state, false)?;

        // Mark the to-be-sealed sectors as no longer accepting data.
        for sector in to_be_sealed.iter() {
            let _ = locked_staged_state
                .sectors_accepting_data
                .remove(&sector.sector_id);
        }

        // Schedule the seal ops in the seal-specific queue.
        let (tx, _) = mpsc::channel();
        let tx = Arc::new(Mutex::new(tx));

        for sector in to_be_sealed {
            // TODO: Do something with any errors encountered while sealing.
            self.seal_tx
                .send(Task::Seal(sector.sector_id, tx.clone()))
                .unwrap();
        }

        Ok(destination_sector_id)
    }

    // If the provided sector id corresponds to SealedSectorMetadata, this
    // method will produce a clone of that metadata.
    pub fn find_sealed_sector_metadata(
        &self,
        sector_id: SectorId,
    ) -> Result<Option<SealedSectorMetadata>> {
        find_sealed_sector_metadata(&self.state, sector_id)
    }

    // For demo purposes. Schedules sealing of all staged sectors.
    fn seal_all_staged_sectors(&self) -> Result<()> {
        let mut locked_staged_state = self.state.staged.lock().unwrap();

        let to_be_sealed = get_sectors_ready_for_sealing(&locked_staged_state, true)?;

        // Mark the to-be-sealed sectors as no longer accepting data.
        for sector in to_be_sealed.iter() {
            let _ = locked_staged_state
                .sectors_accepting_data
                .remove(&sector.sector_id);
        }

        let (tx, _) = mpsc::channel();
        let tx = Arc::new(Mutex::new(tx));

        for sector in to_be_sealed {
            // TODO: Do something with any errors encountered while sealing.
            self.seal_tx
                .send(Task::Seal(sector.sector_id, tx.clone()))
                .unwrap();
        }

        Ok(())
    }
}

impl Drop for SectorBuilder {
    fn drop(&mut self) {
        // Shut down the seal workers.
        for _ in &mut self.seal_workers {
            self.seal_tx.send(Task::Shutdown).unwrap();
        }

        for worker in &mut self.seal_workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}
