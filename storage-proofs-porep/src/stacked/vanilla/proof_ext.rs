use scheduler_client::{
    register, schedule_one_of, ResourceAlloc, ResourceMemory, ResourceReq, ResourceType, TaskFunc,
    TaskReqBuilder, TaskResult, TaskType,
};
use std::time::Duration;
use storage_proofs_core::error::{Error, Result};

// TODO: We need to define if this is going to be part of the configuration file
// as well as an appropiate value for this.
const TIMEOUT: u64 = 3600;

pub(crate) struct Builder<F>
where
    for<'a> F: FnMut(Option<&'a ResourceAlloc>) -> Result<TaskResult, Error>,
{
    call: F,
    num_iter: usize,
}

impl<F> Builder<F>
where
    for<'a> F: FnMut(Option<&'a ResourceAlloc>) -> Result<TaskResult, Error>,
{
    pub(crate) fn new(call: F, num_iter: usize) -> Self {
        Self { call, num_iter }
    }

    pub(crate) fn build(&mut self) -> Result<(), Error> {
        let requirements = {
            let resouce_req = ResourceReq {
                resource: ResourceType::Gpu(ResourceMemory::All),
                quantity: 1,
                preemptible: self.num_iter > 1,
            };
            let task_req = TaskReqBuilder::new()
                .with_task_type(TaskType::MerkleProof)
                .resource_req(resouce_req);
            task_req.build()
        };
        use rand::Rng;
        let mut rng = rand::thread_rng();
        // get the scheduler client
        let id = rng.gen::<u32>();
        let client = register::<Error>(id, id as _)?;

        schedule_one_of(client, self, requirements, Duration::from_secs(TIMEOUT)).map(|_| ())
    }
}

impl<F> TaskFunc for Builder<F>
where
    for<'a> F: FnMut(Option<&'a ResourceAlloc>) -> Result<TaskResult, Error>,
{
    type Output = ();
    type Error = Error;

    fn init(&mut self, _alloc: Option<&ResourceAlloc>) -> Result<Self::Output, Self::Error> {
        Ok(())
    }
    fn end(&mut self, _: Option<&ResourceAlloc>) -> Result<Self::Output, Self::Error> {
        Ok(())
    }

    fn task(&mut self, alloc: Option<&ResourceAlloc>) -> Result<TaskResult, Self::Error> {
        (self.call)(alloc)
    }
}
