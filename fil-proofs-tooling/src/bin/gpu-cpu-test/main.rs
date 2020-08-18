//requires nightly, or later stable version
//#![warn(clippy::unwrap_used)]

use std::collections::HashMap;
use std::process::{self, Child, Command, Stdio};
use std::str;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use clap::{arg_enum, value_t, App, Arg};
use fil_proofs_tooling::shared::{create_replica, PROVER_ID, RANDOMNESS};
use filecoin_proofs::constants::{SectorShape8MiB, SECTOR_SIZE_8_MIB};
use filecoin_proofs::types::{PoStConfig, SectorSize};
use filecoin_proofs::{
    generate_winning_post, PoStType, PrivateReplicaInfo, WINNING_POST_CHALLENGE_COUNT,
    WINNING_POST_SECTOR_COUNT,
};
use log::{debug, info};
use storage_proofs::sector::SectorId;

type MerkleTree = SectorShape8MiB;
const SECTOR_SIZE: u64 = SECTOR_SIZE_8_MIB;
const TIMEOUT: u64 = 5 * 60;
const POST_CONFIG: PoStConfig = PoStConfig {
    sector_size: SectorSize(SECTOR_SIZE),
    challenge_count: WINNING_POST_CHALLENGE_COUNT,
    sector_count: WINNING_POST_SECTOR_COUNT,
    typ: PoStType::Winning,
    priority: false,
};

arg_enum! {
    #[derive(Debug)]
    pub enum Mode {
        Threads,
        Processes,
    }
}

#[derive(Debug)]
pub struct RunInfo {
    elapsed: Duration,
    iterations: u8,
}

pub fn colored_with_thread(
    writer: &mut dyn std::io::Write,
    now: &mut flexi_logger::DeferredNow,
    record: &flexi_logger::Record,
) -> Result<(), std::io::Error> {
    let level = record.level();
    write!(
        writer,
        "{} {} {} {} {} > {}",
        now.now().format("%Y-%m-%dT%H:%M:%S%.3f"),
        process::id(),
        thread::current()
            .name()
            .unwrap_or(&format!("{:?}", thread::current().id())),
        flexi_logger::style(level, level),
        record.module_path().unwrap_or("<unnamed>"),
        record.args(),
    )
}

fn generate_post(priv_replica_info: &[(SectorId, PrivateReplicaInfo<MerkleTree>)]) {
    generate_winning_post::<MerkleTree>(&POST_CONFIG, &RANDOMNESS, priv_replica_info, PROVER_ID)
        .expect("failed to generate PoSt");
}

fn generate_post_in_priority(priv_replica_info: &[(SectorId, PrivateReplicaInfo<MerkleTree>)]) {
    let mut post_config = POST_CONFIG;
    post_config.priority = true;
    generate_winning_post::<MerkleTree>(&post_config, &RANDOMNESS, priv_replica_info, PROVER_ID)
        .expect("failed to generate PoSt with high priority");
}

fn thread_fun(
    rx: Receiver<()>,
    gpu_stealing: bool,
    priv_replica_infos: &[(SectorId, PrivateReplicaInfo<MerkleTree>)],
) -> RunInfo {
    let timing = Instant::now();
    let mut iteration = 0;
    while iteration < std::u8::MAX {
        info!("iter {}", iteration);

        // This is the higher priority proof, get it on the GPU even if there is one running
        // already there
        if gpu_stealing {
            // Run the actual proof
            generate_post_in_priority(&priv_replica_infos);
        } else {
            // Run the actual proof
            generate_post(&priv_replica_infos);
        }

        // Waiting for this thread to be killed
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => {
                debug!("High priority proofs received kill message");
                break;
            }
            Err(TryRecvError::Empty) => (),
        }
        iteration += 1;
    }
    RunInfo {
        elapsed: timing.elapsed(),
        iterations: iteration,
    }
}

fn spawn_thread(
    name: &str,
    gpu_stealing: bool,
    priv_replica_info: (SectorId, PrivateReplicaInfo<MerkleTree>),
) -> (Sender<()>, thread::JoinHandle<RunInfo>) {
    let (tx, rx) = mpsc::channel();

    let thread_config = thread::Builder::new().name(name.to_string());
    let handler = thread_config
        .spawn(move || -> RunInfo { thread_fun(rx, gpu_stealing, &[priv_replica_info]) })
        .expect("Could not spawn thread");

    (tx, handler)
}

fn threads_mode(parallel: u8, gpu_stealing: bool) {
    // All channels we send a termination message to
    let mut senders = Vec::new();
    // All thread handles that get terminated
    let mut threads: Vec<Option<thread::JoinHandle<_>>> = Vec::new();
    let arbitrary_porep_id = [234; 32];

    // Create fixtures only once for both threads
    let (sector_id, replica_output) = create_replica::<MerkleTree>(SECTOR_SIZE, arbitrary_porep_id);
    let priv_replica_info = (sector_id, replica_output.private_replica_info);

    // Put each proof into it's own scope (the other one is due to the if statement)
    {
        let (tx, handler) = spawn_thread("high", gpu_stealing, priv_replica_info.clone());
        senders.push(tx);
        threads.push(Some(handler));
    }

    (1..parallel).for_each(|ii| {
        let name = format!("low-{:02}", ii);
        let (tx, handler) = spawn_thread(&name, false, priv_replica_info.clone());
        senders.push(tx);
        threads.push(Some(handler));
    });

    // Terminate all threads after that amount of time
    let timeout = Duration::from_secs(TIMEOUT);
    thread::sleep(timeout);
    info!("Waited long enough to kill all threads");
    for tx in senders {
        tx.send(()).expect("tx channel send failed");
    }

    for thread in &mut threads {
        if let Some(handler) = thread.take() {
            let thread_name = handler
                .thread()
                .name()
                .unwrap_or(&format!("{:?}", handler.thread().id()))
                .to_string();
            let run_info = handler.join().expect("thread being joined has panicked");
            info!("Thread {} info: {:?}", thread_name, run_info);
            // Also print it, so that we can get that information in processes mode
            println!("Thread {} info: {:?}", thread_name, run_info);
        }
    }
}

fn processes_mode(parallel: u8, gpu_stealing: bool) {
    let mut children = HashMap::new();

    // Put each process into it's own scope (the other one is due to the if statement)
    {
        let name = "high";
        let child = spawn_process(&name, gpu_stealing);
        children.insert(name.to_string(), child);
    }

    (1..parallel).for_each(|ii| {
        let name = format!("low-{:02}", ii);
        let child = spawn_process(&name, false);
        children.insert(name, child);
    });

    // Wait for all processes to finish and log their output
    for (name, child) in children {
        let output = child.wait_with_output().expect("failed to wait for child");
        info!(
            "Process {} info: {}",
            name,
            str::from_utf8(&output.stdout).expect("failed to parse UTF-8")
        );
    }
}

fn spawn_process(name: &str, gpu_stealing: bool) -> Child {
    // Runs this this programm again in it's own process, but this time it is spawning a single
    // thread to run the actual proof.
    Command::new("cargo")
        .arg("run")
        .arg("--release")
        .args(&["--bin", "gpu-cpu-test"])
        .arg("--")
        .args(&["--gpu-stealing", &gpu_stealing.to_string()])
        .args(&["--parallel", "1"])
        .args(&["--mode", "threads"])
        // Print logging to the main process stderr
        .stderr(Stdio::inherit())
        // Use the stdout to return a result
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|_| panic!("failed to execute process {}", name))
}

fn main() {
    flexi_logger::Logger::with_env()
        .format(colored_with_thread)
        .start()
        .expect("Initializing logger failed. Was another logger already initialized?");

    let matches = App::new("gpu-cpu-test")
        .version("0.1")
        .about("Tests if moving proofs from GPU to CPU works")
        .arg(
            Arg::with_name("parallel")
                .long("parallel")
                .help("Run multiple proofs in parallel.")
                .default_value("3"),
        )
        .arg(
            Arg::with_name("gpu-stealing")
                .long("gpu-stealing")
                .help("Force high priority proof on the GPU and let low priority one continue on CPU.")
                .default_value("true"),
        )
        .arg(
            Arg::with_name("mode")
              .long("mode")
              .help("Whether to run with threads or processes.")
               .possible_values(&["threads", "processes"])
               .case_insensitive(true)
               .default_value("threads"),
        )
        .get_matches();

    let parallel = value_t!(matches, "parallel", u8).expect("failed to get parallel");
    if parallel == 1 {
        info!("Running high priority proof only")
    } else {
        info!("Running high and low priority proofs in parallel")
    }
    let gpu_stealing = value_t!(matches, "gpu-stealing", bool).expect("failed to get gpu-stealing");
    if gpu_stealing {
        info!("Force low piority proofs to CPU")
    } else {
        info!("Let everyone queue up to run on GPU")
    }
    let mode = value_t!(matches, "mode", Mode).unwrap_or_else(|e| e.exit());
    match mode {
        Mode::Threads => info!("Using threads"),
        Mode::Processes => info!("Using processes"),
    }

    match mode {
        Mode::Threads => {
            threads_mode(parallel, gpu_stealing);
        }
        Mode::Processes => {
            processes_mode(parallel, gpu_stealing);
        }
    }
}
