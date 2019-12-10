#[cfg(feature = "metrics")]
use std::sync::mpsc::{channel, Receiver, Sender};
#[cfg(feature = "metrics")]
use std::sync::Mutex;
#[cfg(not(feature = "metrics"))]
use std::time::Duration;
#[cfg(feature = "metrics")]
use std::time::{Duration, Instant};

#[cfg(feature = "metrics")]
use cpu_time::ProcessTime;

use serde::Serialize;

#[cfg(feature = "metrics")]
use lazy_static::lazy_static;

#[cfg(feature = "metrics")]
lazy_static! {
    pub static ref OP_MEASUREMENTS: (
        Mutex<Option<Sender<OpMeasurement>>>,
        Mutex<Receiver<OpMeasurement>>
    ) = {
        // create asynchronous channel with unlimited buffer
        let (tx, rx) = channel();
        (Mutex::new(Some(tx)), Mutex::new(rx))
    };
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct OpMeasurement {
    pub op: Operation,
    pub cpu_time: Duration,
    pub wall_time: Duration,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    GenerateTreeC,
    GenerateTreeRLast,
    CommD,
    EncodeWindowTimeAll,
    WindowCommLeavesTime,
    PorepCommitTime,
}

#[cfg(feature = "metrics")]
pub fn measure_op<T, F>(op: Operation, f: F) -> anyhow::Result<T>
where
    F: FnOnce() -> anyhow::Result<T>,
{
    let cpu_time_start = ProcessTime::now();
    let wall_start_time = Instant::now();

    let x = f()?;

    let opt_tx = OP_MEASUREMENTS
        .0
        .lock()
        .expect("acquire lock on tx side of perf channel");

    if let Some(tx) = opt_tx.as_ref() {
        tx.clone()
            .send(OpMeasurement {
                op,
                cpu_time: cpu_time_start.elapsed(),
                wall_time: wall_start_time.elapsed(),
            })
            .expect("failed to send to perf channel");
    }

    Ok(x)
}

#[cfg(not(feature = "metrics"))]
pub fn measure_op<T, F>(_: Operation, f: F) -> anyhow::Result<T>
where
    F: FnOnce() -> anyhow::Result<T>,
{
    f()
}
