use api::sector_builder::helpers::add_piece::*;
use api::sector_builder::helpers::get_seal_status::*;
use api::sector_builder::helpers::get_sectors_ready_for_sealing::*;
use api::sector_builder::helpers::read_piece_from_sealed_sector::read_piece_from_sealed_sector;
use api::sector_builder::helpers::snapshots::{load_snapshot, make_snapshot, persist_snapshot};
use api::sector_builder::kv_store::fs::FileSystemKvs;
use api::sector_builder::kv_store::KeyValueStore;
use api::sector_builder::metadata::*;
use api::sector_builder::state::*;
use api::sector_builder::worker::*;
use error::Result;
use sector_base::api::disk_backed_storage::new_sector_store;
use sector_base::api::disk_backed_storage::SBConfiguredStore;
use sector_base::api::sector_store::SectorStore;
use std::sync::{mpsc, Arc, Mutex};

pub mod errors;
mod helpers;
mod kv_store;
pub mod metadata;
mod state;
mod worker;

const NUM_SEAL_WORKERS: usize = 2;

pub type SectorId = u64;

pub struct SectorBuilder {
    // Provides thread-safe access to a KeyValueStore, used to save/load
    // SectorBuilder metadata.
    kv_store: Arc<WrappedKeyValueStore>,

    // Provides thread-safe access to a SectorStore, used to interact with
    // sector storage.
    //
    // TODO: Non-boxed trait objects, have a size which is unknown at compile
    // time. A reference, e.g. &SectorStore does have a known size, but is not
    // thread safe w/out an Arc. For now, the SectorBuilder owns the concrete
    // type, which we can retrieve from an Arc and transmute to a &SectorStore
    // value for the internal::seal function. In the future (soon), we need to
    // figure out if the internal::seal API needs to change or if there's some
    // other way to allow thread-safe access to a shared SectorStore.
    sector_store: Arc<WrappedSectorStore>,

    // A reference-counted struct which holds all SectorBuilder state. Mutable
    // fields are Mutex-guarded.
    state: Arc<SectorBuilderState>,

    // A work queue which should only be sent Task::Seal. Prevents FFI consumers
    // from queueing behind long-running seal operations.
    seal_tx: mpsc::Sender<Task>,

    // For additional seal concurrency, add more workers here.
    seal_workers: Vec<Worker>,

    // Configures the maximum number of staged sectors which can be open and
    // accepting data at any point in time.
    max_num_staged_sectors: u8,

    // Configures the maximum number of user piece-bytes which will fit into a
    // freshly-provisioned staged sector.
    max_user_bytes_per_staged_sector: u64,
}

pub struct WrappedSectorStore {
    inner: Box<SectorStore>,
}

unsafe impl Sync for WrappedSectorStore {}
unsafe impl Send for WrappedSectorStore {}

pub struct WrappedKeyValueStore {
    inner: Box<KeyValueStore>,
}

unsafe impl Sync for WrappedKeyValueStore {}
unsafe impl Send for WrappedKeyValueStore {}

impl SectorBuilder {
    // Initialize and return a SectorBuilder from metadata persisted to disk if
    // it exists. Otherwise, initialize and return a fresh SectorBuilder. The
    // metadata key is equal to the prover_id.
    //
    // TODO: As of now, this function will always return a new SectorBuilder. A
    // real metadata store is forthcoming.
    pub fn init_from_metadata<S: Into<String>>(
        sector_store_config: &SBConfiguredStore,
        last_committed_sector_id: u64,
        metadata_dir: S,
        prover_id: [u8; 31],
        sealed_sector_dir: S,
        staged_sector_dir: S,
        max_num_staged_sectors: u8,
    ) -> Result<SectorBuilder> {
        let kv_store = Arc::new(WrappedKeyValueStore {
            inner: Box::new(FileSystemKvs::initialize(metadata_dir.into())?),
        });

        // Build the SectorBuilder's initial state. If available, we
        // reconstitute this stage from persisted metadata. If not, we create it
        // from scratch.
        let state = {
            let loaded = load_snapshot(&kv_store, &prover_id)?;
            let loaded = loaded.map(|x| x.into());

            Arc::new(loaded.unwrap_or_else(|| SectorBuilderState {
                prover_id,
                staged: Mutex::new(StagedState {
                    sector_id_nonce: last_committed_sector_id,
                    sectors: Default::default(),
                    sectors_accepting_data: Default::default(),
                }),
                sealed: Default::default(),
            }))
        };

        // Initialize a SectorStore and wrap it in an Arc so we can access it
        // from multiple threads. Our implementation assumes that the
        // SectorStore is safe for concurrent access.
        let sector_store = Arc::new(WrappedSectorStore {
            inner: Box::new(new_sector_store(
                sector_store_config,
                sealed_sector_dir.into(),
                staged_sector_dir.into(),
            )),
        });

        // Configure seal queue workers and channels.
        let (seal_tx, seal_workers) = {
            let (tx, rx) = mpsc::channel();
            let rx = Arc::new(Mutex::new(rx));

            let workers = (0..NUM_SEAL_WORKERS)
                .map(|n| {
                    Worker::new(
                        n,
                        Arc::clone(&rx),
                        Arc::clone(&kv_store),
                        Arc::clone(&sector_store),
                        Arc::clone(&state),
                    )
                })
                .collect();

            (tx, workers)
        };

        let max_user_bytes_per_staged_sector = sector_store
            .clone()
            .inner
            .config()
            .max_unsealed_bytes_per_sector();

        Ok(SectorBuilder {
            kv_store,
            seal_tx,
            seal_workers,
            sector_store,
            state,
            max_num_staged_sectors,
            max_user_bytes_per_staged_sector,
        })
    }

    // Returns the number of user-provided bytes that will fit into a staged
    // sector.
    pub fn get_max_user_bytes_per_staged_sector(&self) -> u64 {
        self.max_user_bytes_per_staged_sector
    }

    // Stages user piece-bytes for sealing. Note that add_piece calls are
    // processed sequentially to make bin packing easier.
    pub fn add_piece<S: Into<String>>(&self, piece_key: S, piece_bytes: &[u8]) -> Result<SectorId> {
        let mut staged_state = self.state.staged.lock().unwrap();

        // Write the piece to storage, obtaining the sector id with which the
        // piece-bytes are now associated.
        let destination_sector_id = add_piece(
            &self.sector_store,
            &mut staged_state,
            piece_key,
            piece_bytes,
        )?;

        let to_be_sealed = get_sectors_ready_for_sealing(
            &staged_state,
            self.max_user_bytes_per_staged_sector,
            self.max_num_staged_sectors,
            false,
        );

        // Mark the to-be-sealed sectors as no longer accepting data.
        for sector in to_be_sealed.iter() {
            let _ = staged_state
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

        // Snapshot the SectorBuilder's state. As the state includes both sealed
        // and staged state-maps, making a snapshot requires both locks.
        let sealed_state = self.state.sealed.lock().unwrap();
        let snapshot = make_snapshot(&self.state.prover_id, &staged_state, &sealed_state);
        persist_snapshot(&self.kv_store, &snapshot)?;

        Ok(destination_sector_id)
    }

    // Returns sealing status for the sector with specified id. If no sealed or
    // staged sector exists with the provided id, produce an error.
    pub fn get_seal_status(&self, sector_id: SectorId) -> Result<SealStatus> {
        let sealed_state = self.state.sealed.lock().unwrap();
        let staged_state = self.state.staged.lock().unwrap();

        get_seal_status(&staged_state, &sealed_state, sector_id)
    }

    pub fn read_piece_from_sealed_sector<S: Into<String>>(&self, piece_key: S) -> Result<Vec<u8>> {
        let sealed_state = self.state.sealed.lock().unwrap();

        read_piece_from_sealed_sector(
            &self.sector_store,
            &sealed_state,
            self.state.prover_id,
            piece_key,
        )
    }

    // For demo purposes. Schedules sealing of all staged sectors.
    pub fn seal_all_staged_sectors(&self) -> Result<()> {
        let mut locked_staged_state = self.state.staged.lock().unwrap();

        let to_be_sealed = get_sectors_ready_for_sealing(
            &locked_staged_state,
            self.max_user_bytes_per_staged_sector,
            self.max_num_staged_sectors,
            true,
        );

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

    pub fn get_sealed_sectors(&self) -> Result<Vec<SealedSectorMetadata>> {
        Ok(self
            .state
            .sealed
            .lock()
            .unwrap()
            .sectors
            .values()
            .cloned()
            .collect())
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
