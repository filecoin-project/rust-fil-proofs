use api::sector_builder::helpers::seal::seal;
use api::sector_builder::metadata::SealedSectorMetadata;
use api::sector_builder::state::SectorBuilderState;
use api::sector_builder::SectorId;
use error::Result;
use sector_base::api::disk_backed_storage::ConcreteSectorStore;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct Worker {
    pub id: usize,
    pub thread: Option<thread::JoinHandle<()>>,
}

pub enum Task {
    Seal(SectorId, Arc<Mutex<Sender<Result<SealedSectorMetadata>>>>),
    Shutdown,
}

impl Worker {
    pub fn new(
        id: usize,
        task_rx: Arc<Mutex<mpsc::Receiver<Task>>>,
        sector_store: Arc<ConcreteSectorStore>,
        sector_builder_state: Arc<SectorBuilderState>,
    ) -> Worker {
        let thread = thread::spawn(move || loop {
            // Acquire a lock on the rx end of the channel, get a task,
            // relinquish the lock and return the task.
            let task = {
                let rx = task_rx.lock().unwrap();
                rx.recv().unwrap()
            };

            // Increment the reference counts, shadowing constructor parameters
            // for convenience.
            let store = sector_store.clone();
            let state = sector_builder_state.clone();

            // Dispatch to the appropriate task-handler.
            match task {
                Task::Seal(sector_id, done_tx) => {
                    let done_tx = done_tx.lock().unwrap();
                    let _ = done_tx.send(seal(&store, &state, sector_id));
                }
                Task::Shutdown => break,
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}
