use crate::api::sector_builder::helpers::retrieve_piece::retrieve_piece;
use crate::api::sector_builder::helpers::seal::seal;
use crate::api::sector_builder::metadata::SealedSectorMetadata;
use crate::api::sector_builder::metadata::StagedSectorMetadata;
use crate::api::sector_builder::scheduler::Request;
use crate::api::sector_builder::WrappedSectorStore;
use crate::error::ErrorLogResult;
use crate::error::Result;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct SealerWorker {
    pub id: usize,
    pub thread: Option<thread::JoinHandle<()>>,
}

pub enum SealerInput {
    Seal(StagedSectorMetadata, mpsc::SyncSender<Request>),
    Unseal(
        String,
        Box<SealedSectorMetadata>,
        mpsc::SyncSender<Result<Vec<u8>>>,
    ),
    Shutdown,
}

impl SealerWorker {
    pub fn start(
        id: usize,
        seal_task_rx: Arc<Mutex<mpsc::Receiver<SealerInput>>>,
        sector_store: Arc<WrappedSectorStore>,
        prover_id: [u8; 31],
    ) -> SealerWorker {
        let thread = thread::spawn(move || loop {
            // Acquire a lock on the rx end of the channel, get a task,
            // relinquish the lock and return the task. The receiver is mutexed
            // for coordinating reads across multiple worker-threads.
            let task = {
                let rx = seal_task_rx
                    .lock()
                    .expect_with_logging("error acquiring task lock");
                rx.recv().expect_with_logging("error receiving seal task")
            };

            // Dispatch to the appropriate task-handler.
            match task {
                SealerInput::Seal(staged_sector, return_channel) => {
                    let sector_id = staged_sector.sector_id;
                    let result = seal(&sector_store.clone(), &prover_id, staged_sector);
                    let task = Request::HandleSealResult(sector_id, Box::new(result));

                    return_channel
                        .send(task)
                        .expect_with_logging("error sending task");
                }
                SealerInput::Unseal(piece_key, sealed_sector, return_channel) => {
                    let result = retrieve_piece(
                        &sector_store.clone(),
                        &sealed_sector,
                        &prover_id,
                        &piece_key,
                    );

                    return_channel
                        .send(result)
                        .expect_with_logging("error sending result");
                }
                SealerInput::Shutdown => break,
            }
        });

        SealerWorker {
            id,
            thread: Some(thread),
        }
    }
}
