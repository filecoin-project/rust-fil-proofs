#[cfg(feature = "measurements")]
use std::sync::mpsc::{channel, Receiver, Sender};
#[cfg(feature = "measurements")]
use std::sync::Mutex;
#[cfg(not(feature = "measurements"))]
use std::time::Duration;
#[cfg(feature = "measurements")]
use std::time::{Duration, Instant};

#[cfg(feature = "measurements")]
use cpu_time::ProcessTime;

#[cfg(feature = "prometheus")]
use prometheus::*;
#[cfg(feature = "prometheus")]
use std::collections::HashMap;

use serde::Serialize;

#[cfg(feature = "measurements")]
use lazy_static::lazy_static;

#[cfg(feature = "measurements")]
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

#[derive(PartialEq, Eq, Clone, Copy, Hash, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    AddPiece,
    GeneratePieceCommitment,
    GenerateTreeC,
    GenerateTreeRLast,
    CommD,
    EncodeWindowTimeAll,
    WindowCommLeavesTime,
    PorepCommitTime,
    PostInclusionProofs,
    PostFinalizeTicket,
    PostReadChallengedRange,
    PostPartialTicketHash,
}

#[cfg(feature = "prometheus")]
const HISTOGRAMED_OPS: &[Operation] = &[
    Operation::AddPiece,
    Operation::GeneratePieceCommitment,
    Operation::GenerateTreeC,
    Operation::GenerateTreeRLast,
    Operation::CommD,
];

#[cfg(feature = "prometheus")]
lazy_static! {
    static ref PROMETHEUS_HISTOGRAMS: HashMap<Operation, Histogram> = {
        let mut hists = HashMap::new();
        for op in HISTOGRAMED_OPS {
            hists.insert(
                *op,
                register_histogram!(format!("{:?}", op), format!("{:?}", op)).unwrap(),
            );
        }
        hists
    };
}

#[cfg(feature = "prometheus")]
use hyper::{header::CONTENT_TYPE, Body, Request, Response};

#[cfg(feature = "prometheus")]
pub async fn prometheus_server(
    _req: Request<Body>,
) -> std::result::Result<Response<Body>, hyper::Error> {
    let encoder = TextEncoder::new();

    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))
        .unwrap();

    Ok(response)
}

#[cfg(feature = "measurements")]
pub fn measure_op<T, F>(op: Operation, f: F) -> T
where
    F: FnOnce() -> T,
{
    let cpu_time_start = ProcessTime::now();
    let wall_start_time = Instant::now();

    #[cfg(feature = "profile")]
    gperftools::profiler::PROFILER
        .lock()
        .unwrap()
        .start(format!("./{:?}.profile", op))
        .unwrap();
    let x = f();
    #[cfg(feature = "profile")]
    gperftools::profiler::PROFILER
        .lock()
        .unwrap()
        .stop()
        .unwrap();

    let opt_tx = OP_MEASUREMENTS
        .0
        .lock()
        .expect("acquire lock on tx side of perf channel");

    let cpu_time = cpu_time_start.elapsed();
    let wall_time = wall_start_time.elapsed();

    #[cfg(feature = "prometheus")]
    {
        if let Some(hist) = PROMETHEUS_HISTOGRAMS.get(&op) {
            hist.observe(wall_time.as_secs_f64());
        }
    }

    if let Some(tx) = opt_tx.as_ref() {
        tx.clone()
            .send(OpMeasurement {
                op,
                cpu_time,
                wall_time,
            })
            .expect("failed to send to perf channel");
    }

    x
}

#[cfg(not(feature = "measurements"))]
pub fn measure_op<T, F>(_: Operation, f: F) -> T
where
    F: FnOnce() -> T,
{
    f()
}
