use crate::api::sector_builder::kv_store::fs::FileSystemKvs;
use crate::api::sector_builder::kv_store::KeyValueStore;
use crate::api::sector_builder::metadata::*;
use crate::api::sector_builder::scheduler::Request;
use crate::api::sector_builder::scheduler::Scheduler;
use crate::api::sector_builder::sealer::*;
use crate::error::Result;
use sector_base::api::disk_backed_storage::new_sector_store;
use sector_base::api::disk_backed_storage::SBConfiguredStore;
use sector_base::api::sector_store::SectorStore;
use std::sync::{mpsc, Arc, Mutex};

pub mod errors;
mod helpers;
mod kv_store;
pub mod metadata;
mod scheduler;
mod sealer;
mod state;

const NUM_SEAL_WORKERS: usize = 2;

const FATAL_NOSEND_TASK: &str = "[run_blocking] could not send";
const FATAL_NORECV_TASK: &str = "[run_blocking] could not recv";

pub type SectorId = u64;

pub struct SectorBuilder {
    // Prevents FFI consumers from queueing behind long-running seal operations.
    sealers_tx: mpsc::Sender<SealerInput>,

    // For additional seal concurrency, add more workers here.
    sealers: Vec<SealerWorker>,

    // The main worker's queue.
    scheduler_tx: mpsc::SyncSender<Request>,

    // The main worker. Owns all mutable state for the SectorBuilder.
    scheduler: Scheduler,
}

impl SectorBuilder {
    // Initialize and return a SectorBuilder from metadata persisted to disk if
    // it exists. Otherwise, initialize and return a fresh SectorBuilder. The
    // metadata key is equal to the prover_id.
    pub fn init_from_metadata<S: Into<String>>(
        sector_store_config: &SBConfiguredStore,
        last_committed_sector_id: SectorId,
        metadata_dir: S,
        prover_id: [u8; 31],
        sealed_sector_dir: S,
        staged_sector_dir: S,
        max_num_staged_sectors: u8,
    ) -> Result<SectorBuilder> {
        let kv_store = Arc::new(WrappedKeyValueStore {
            inner: Box::new(FileSystemKvs::initialize(metadata_dir.into())?),
        });

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

        // Configure the main worker's rendezvous channel.
        let (main_tx, main_rx) = mpsc::sync_channel(0);

        // Configure seal queue workers and channels.
        let (seal_tx, seal_workers) = {
            let (tx, rx) = mpsc::channel();
            let rx = Arc::new(Mutex::new(rx));

            let workers = (0..NUM_SEAL_WORKERS)
                .map(|n| SealerWorker::start(n, rx.clone(), sector_store.clone(), prover_id))
                .collect();

            (tx, workers)
        };

        // Configure main worker.
        let main_worker = Scheduler::start_with_metadata(
            main_rx,
            main_tx.clone(),
            seal_tx.clone(),
            kv_store.clone(),
            sector_store.clone(),
            last_committed_sector_id,
            max_num_staged_sectors,
            prover_id,
        );

        Ok(SectorBuilder {
            scheduler_tx: main_tx,
            scheduler: main_worker,
            sealers_tx: seal_tx,
            sealers: seal_workers,
        })
    }

    // Returns the number of user-provided bytes that will fit into a staged
    // sector.
    pub fn get_max_user_bytes_per_staged_sector(&self) -> u64 {
        self.run_blocking(Request::GetMaxUserBytesPerStagedSector)
    }

    // Stages user piece-bytes for sealing. Note that add_piece calls are
    // processed sequentially to make bin packing easier.
    pub fn add_piece(&self, piece_key: String, piece_bytes: &[u8]) -> Result<SectorId> {
        self.run_blocking(|tx| Request::AddPiece(piece_key, piece_bytes.to_vec(), tx))
    }

    // Returns sealing status for the sector with specified id. If no sealed or
    // staged sector exists with the provided id, produce an error.
    pub fn get_seal_status(&self, sector_id: SectorId) -> Result<SealStatus> {
        self.run_blocking(|tx| Request::GetSealStatus(sector_id, tx))
    }

    // Unseals the sector containing the referenced piece and returns its
    // bytes. Produces an error if this sector builder does not have a sealed
    // sector containing the referenced piece.
    pub fn read_piece_from_sealed_sector(&self, piece_key: String) -> Result<Vec<u8>> {
        self.run_blocking(|tx| Request::RetrievePiece(piece_key, tx))
    }

    // For demo purposes. Schedules sealing of all staged sectors.
    pub fn seal_all_staged_sectors(&self) -> Result<()> {
        self.run_blocking(Request::SealAllStagedSectors)
    }

    // Produce a slice of all sealed sector metadata.
    pub fn get_sealed_sectors(&self) -> Result<Vec<SealedSectorMetadata>> {
        self.run_blocking(Request::GetSealedSectors)
    }

    // Run a task, blocking on the return channel.
    fn run_blocking<T, F: FnOnce(mpsc::SyncSender<T>) -> Request>(&self, with_sender: F) -> T {
        let (tx, rx) = mpsc::sync_channel(0);

        self.scheduler_tx
            .clone()
            .send(with_sender(tx))
            .expect(FATAL_NOSEND_TASK);

        rx.recv().expect(FATAL_NORECV_TASK)
    }
}

impl Drop for SectorBuilder {
    fn drop(&mut self) {
        // Shut down main worker and sealers, too.
        let _ = self
            .scheduler_tx
            .send(Request::Shutdown)
            .map_err(|err| println!("err sending Shutdown to scheduler: {:?}", err));

        for _ in &mut self.sealers {
            let _ = self
                .sealers_tx
                .send(SealerInput::Shutdown)
                .map_err(|err| println!("err sending Shutdown to sealer: {:?}", err));
        }

        // Wait for worker threads to return.
        let scheduler_thread = &mut self.scheduler.thread;

        if let Some(thread) = scheduler_thread.take() {
            let _ = thread
                .join()
                .map_err(|err| println!("err joining scheduler thread: {:?}", err));
        }

        for worker in &mut self.sealers {
            if let Some(thread) = worker.thread.take() {
                let _ = thread
                    .join()
                    .map_err(|err| println!("err joining sealer thread: {:?}", err));
            }
        }
    }
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
