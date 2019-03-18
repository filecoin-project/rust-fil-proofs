#[macro_use]
extern crate serde;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate clap;
extern crate glob;
extern crate human_size;
extern crate permutate;
extern crate prettytable;
extern crate serde_json;
extern crate toml;

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::prelude::*;
use std::process::Command;
use std::string::ToString;
use std::time::{Duration, SystemTime};

use clap::{App, Arg};
use failure::Error;
use filecoin_proofs::error::ExpectWithBacktrace;
use glob::glob;
use human_size::{Byte, Kibibyte, SpecificSize};
use permutate::Permutator;
use prettytable::{format, Cell, Row, Table};
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};

type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, Deserialize)]
struct Case {
    command: Option<String>,
    challenges: Vec<usize>,
    size: Vec<Size>,
    sloth: Vec<usize>,
    m: Vec<usize>,
    hasher: Option<Vec<String>>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
struct Size(SpecificSize<Byte>);

impl Default for Size {
    fn default() -> Self {
        Size(SpecificSize::new(0, Byte).unwrap())
    }
}

impl ToString for Size {
    fn to_string(&self) -> String {
        // return as KiB as that is what the examples expect
        let kb: SpecificSize<Kibibyte> = self.0.into();
        kb.value().to_string()
    }
}

impl Serialize for Size {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Size {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SizeVisitor;

        impl<'de> Visitor<'de> for SizeVisitor {
            type Value = Size;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("user ID as a number or string")
            }

            fn visit_u64<E>(self, size: u64) -> ::std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                SpecificSize::new(size as f64, Byte)
                    .map(Size)
                    .map_err(de::Error::custom)
            }

            fn visit_str<E>(self, size: &str) -> ::std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                size.parse().map(Size).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(SizeVisitor)
    }
}

impl Case {
    pub fn params(&self) -> Vec<Vec<String>> {
        let mut res = Vec::with_capacity(4);

        res.push(self.challenges.iter().map(ToString::to_string).collect());
        res.push(self.size.iter().map(ToString::to_string).collect());
        res.push(self.sloth.iter().map(ToString::to_string).collect());
        res.push(self.m.iter().map(ToString::to_string).collect());
        if let Some(ref hasher) = self.hasher {
            res.push(hasher.clone());
        }

        res
    }

    pub fn get_param_name(&self, i: usize) -> Result<String> {
        let params = self.get_param_names();
        if i > params.len() {
            return Err(format_err!("invalid param index {}", i));
        }

        Ok(params[i].to_string())
    }

    pub fn get_param_names(&self) -> Vec<String> {
        let mut res = vec![
            "challenges".to_owned(),
            "size".to_owned(),
            "sloth".to_owned(),
            "m".to_owned(),
        ];

        if self.hasher.is_some() {
            res.push("hasher".to_owned());
        }

        res
    }
}

#[cfg(not(target_os = "macos"))]
const TIME_CMD: &str = "/usr/bin/time";

#[cfg(target_os = "macos")]
const TIME_CMD: &str = "gtime";

/// The directory in which we expect the compiled binaries to be in.
const BINARY_DIR: &str = "target/release/examples";

/// The glob of which files to clear out before starting the run.
const CACHE_DIR: &str = "/tmp/filecoin-proofs-cache-*";

/// The directory in which the benchmark results will be stored.
const RESULT_DIR: &str = ".bencher";

lazy_static! {
    static ref PRELUDE: Vec<(&'static str, Vec<&'static str>)> =
        vec![("cargo", vec!["build", "--all", "--examples", "--release"]),];
    static ref MARKDOWN_TABLE_FORMAT: format::TableFormat = format::FormatBuilder::new()
        .column_separator('|')
        .borders('|')
        .separators(
            &[format::LinePosition::Title],
            format::LineSeparator::new('-', '|', '|', '|'),
        )
        .padding(1, 1)
        .build();
}

fn combine<'a, T: ?Sized>(options: &'a [&'a [&'a T]]) -> Vec<Vec<&'a T>> {
    Permutator::new(options).collect()
}

fn run(config_path: &str, print_table: bool) -> Result<()> {
    println!("reading config \"{}\"...", config_path);

    let mut f = File::open(config_path)?;
    let mut contents = String::new();
    f.read_to_string(&mut contents)?;

    let config: HashMap<String, Case> = toml::from_str(&contents)?;

    println!("preparing...");

    // make sure we are cleaning up the cache
    for file in glob(CACHE_DIR)? {
        fs::remove_file(file?)?;
    }

    for (cmd, args) in &PRELUDE[..] {
        let output = Command::new(cmd).args(args).output()?;
        if !output.status.success() {
            return Err(format_err!(
                "failed to execute '{} {:?}': {} stdout: {}, stdout: {}",
                cmd,
                args,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ));
        }
    }

    for (name, example) in config.iter() {
        let results = run_benchmark(name, example)?;
        if print_table {
            print_result_table(name, example, &results);
        }
    }

    Ok(())
}

fn print_result_table(name: &str, example: &Case, results: &[BenchmarkResult]) {
    let params = example.get_param_names();

    let mut table = Table::new();
    table.set_format(*MARKDOWN_TABLE_FORMAT);

    let mut titles: Vec<&str> = vec![
        "name",
        "size",
        "proving",
        "verifying",
        "params gen",
        "replication",
        "max resident set size",
    ];

    titles.extend(params.iter().map(String::as_str));

    table.set_titles(Row::new(titles.iter().map(|v| Cell::new(v)).collect()));

    for res in results {
        let timing = res.time_res.max_resident_set_size.to_string();
        let mut values: Vec<&str> = vec![
            name,
            &res.log_res.config["data_size"],
            &res.log_res.stats["avg_proving_time"],
            &res.log_res.stats["avg_verifying_time"],
            res.log_res
                .stats
                .get("params_generation_time")
                .map(String::as_str)
                .unwrap_or_else(|| ""),
            res.log_res
                .stats
                .get("replication_time")
                .map(String::as_str)
                .unwrap_or_else(|| ""),
            &timing,
        ];
        values.extend(res.combination.iter().map(String::as_str));

        table.add_row(Row::new(values.into_iter().map(Cell::new).collect()));
    }

    println!("\n");
    table.printstd();
    println!("\n");
}

#[derive(Default, Debug, Serialize)]
struct TimeResult {
    // Command being timed: "/Users/dignifiedquire/work/filecoin/rust-proofs/target/release/examples/drgporep-vanilla --challenges 1 --size 1 --sloth 0 --m 6 --hasher sha256"
    command: String,
    // User time (seconds): 118.33
    user_time: f64,
    // System time (seconds): 1.07
    system_time: f64,
    // Percent of CPU this job got: 959%
    cpu: usize,
    // Elapsed (wall clock) time (h:mm:ss or m:ss): 0:12.44
    elapsed_time: Duration,
    // Average shared text size (kbytes): 0
    avg_shared_text_size: usize,
    // Average unshared data size (kbytes): 0
    avg_unshared_data_size: usize,
    // Average stack size (kbytes): 0
    avg_stack_size: usize,
    // Average total size (kbytes): 0
    avg_total_size: usize,
    // Maximum resident set size (kbytes): 117604
    max_resident_set_size: usize,
    // Average resident set size (kbytes): 0
    avg_resident_set_size: usize,
    // Major (requiring I/O) page faults: 0
    major_page_faults: usize,
    // Minor (reclaiming a frame) page faults: 69788
    minor_page_faults: usize,
    // Voluntary context switches: 7
    voluntary_context_switches: usize,
    // Involuntary context switches: 70063
    involuntary_context_switches: usize,
    // Swaps: 0
    swaps: usize,
    // File system inputs: 0
    file_system_inputs: usize,
    // File system outputs: 0
    file_system_outputs: usize,
    // Socket messages sent: 0
    socket_messages_sent: usize,
    // Socket messages received: 0
    socket_messages_received: usize,
    // Signals delivered: 0
    signals_delivered: usize,
    // Page size (bytes): 4096
    page_size: usize,
    // Exit status: 0
    exit_status: usize,
}

impl TimeResult {
    fn from_str(raw: &str) -> Result<Self> {
        let mut res = TimeResult::default();

        for line in raw.trim().split('\n') {
            let line = line.trim();
            let kv = line.split(": ").collect::<Vec<&str>>();
            let key = kv[0].trim();
            let value = kv[1].trim();

            match key {
                "Command being timed" => {
                    res.command = value.trim_matches('"').to_string();
                }
                "User time (seconds)" => {
                    res.user_time = value.parse()?;
                }
                "System time (seconds)" => {
                    res.system_time = value.parse()?;
                }
                "Percent of CPU this job got" => {
                    res.cpu = value.replace('%', "").parse()?;
                }
                "Elapsed (wall clock) time (h:mm:ss or m:ss)" => {
                    let parts = value.split(':').collect::<Vec<&str>>();
                    match parts.len() {
                        2 => {
                            let minutes = Duration::from_secs(parts[0].parse::<u64>()? * 60);
                            let seconds =
                                Duration::from_millis((parts[1].parse::<f64>()? * 1000.0) as u64);
                            res.elapsed_time = minutes + seconds;
                        }
                        3 => {
                            let hours = Duration::from_secs(parts[0].parse::<u64>()? * 60 * 60);
                            let minutes = Duration::from_secs(parts[1].parse::<u64>()? * 60);
                            let seconds =
                                Duration::from_millis((parts[2].parse::<f64>()? * 1000.0) as u64);
                            res.elapsed_time = hours + minutes + seconds;
                        }
                        _ => return Err(format_err!("invalid time format: '{}'", value)),
                    }
                }
                "Average shared text size (kbytes)" => {
                    res.avg_shared_text_size = value.parse()?;
                }
                "Average unshared data size (kbytes)" => {
                    res.avg_unshared_data_size = value.parse()?;
                }
                "Average stack size (kbytes)" => {
                    res.avg_stack_size = value.parse()?;
                }
                "Average total size (kbytes)" => {
                    res.avg_total_size = value.parse()?;
                }
                "Maximum resident set size (kbytes)" => {
                    res.max_resident_set_size = value.parse()?;
                }
                "Average resident set size (kbytes)" => {
                    res.avg_resident_set_size = value.parse()?;
                }
                "Major (requiring I/O) page faults" => {
                    res.major_page_faults = value.parse()?;
                }
                "Minor (reclaiming a frame) page faults" => {
                    res.minor_page_faults = value.parse()?;
                }
                "Voluntary context switches" => {
                    res.voluntary_context_switches = value.parse()?;
                }
                "Involuntary context switches" => {
                    res.involuntary_context_switches = value.parse()?;
                }
                "Swaps" => {
                    res.swaps = value.parse()?;
                }
                "File system inputs" => {
                    res.file_system_inputs = value.parse()?;
                }
                "File system outputs" => {
                    res.file_system_outputs = value.parse()?;
                }
                "Socket messages sent" => {
                    res.socket_messages_sent = value.parse()?;
                }
                "Socket messages received" => {
                    res.socket_messages_received = value.parse()?;
                }
                "Signals delivered" => {
                    res.signals_delivered = value.parse()?;
                }
                "Page size (bytes)" => {
                    res.page_size = value.parse()?;
                }
                "Exit status" => {
                    res.exit_status = value.parse()?;
                }
                _ => {
                    return Err(format_err!("unknown key: {}", key));
                }
            }
        }

        Ok(res)
    }
}

#[derive(Default, Debug, Serialize)]
struct BenchmarkResult {
    combination: Vec<String>,
    stdout: String,
    stderr: String,
    time_res: TimeResult,
    log_res: LogResult,
}

impl BenchmarkResult {
    pub fn new(combination: &[&str], stdout: &str, stderr: &str) -> Result<Self> {
        // removes the annoying progress bar
        let stderr = "Command being timed".to_owned()
            + stderr.split("Command being timed").collect::<Vec<&str>>()[1];

        let time_res = TimeResult::from_str(&stderr)?;
        let log_res = LogResult::from_str(&stdout)?;

        Ok(BenchmarkResult {
            combination: combination.iter().map(ToString::to_string).collect(),
            stdout: stdout.to_owned(),
            stderr,
            time_res,
            log_res,
        })
    }
}

#[derive(Default, Debug, Serialize)]
struct LogResult {
    config: HashMap<String, String>,
    stats: HashMap<String, String>,
}

impl LogResult {
    fn from_str(raw: &str) -> Result<Self> {
        let lines = raw.trim().split('\n').map(|l| {
            let parsed: serde_json::Result<HashMap<String, String>> = serde_json::from_str(l);
            let parsed = parsed.expects("The bencher requires JSON log-output.");

            let raw = &parsed["msg"];
            let system = parsed.get("target").cloned().unwrap_or_default();
            let kv = raw.trim().split(": ").collect::<Vec<&str>>();
            let key = kv[0].trim();
            let value = if kv.len() > 1 { kv[1].trim() } else { "" };

            (system, String::from(key), String::from(value))
        });

        let mut config = HashMap::new();
        let mut stats = HashMap::new();

        for (system, key, value) in lines {
            match system.as_ref() {
                "config" => {
                    config.insert(key.to_owned(), value.to_owned());
                }
                "stats" => {
                    stats.insert(key.to_owned(), value.to_owned());
                }
                // ignoring unknown subsystems for now
                _ => {}
            }
        }

        Ok(LogResult { config, stats })
    }
}

fn run_benchmark(name: &str, config: &Case) -> Result<Vec<BenchmarkResult>> {
    println!("benchmarking example: {}", name);

    // create dir to store results
    let result_dir = env::current_dir()?.join(RESULT_DIR).join(name);
    fs::create_dir_all(&result_dir)?;

    // the dance below is to avoid copies
    let params = config.params();
    let tmp_1: Vec<Vec<&str>> = params
        .iter()
        .map(|list| list.iter().map(AsRef::as_ref).collect::<Vec<&str>>())
        .collect();
    let tmp_2: Vec<&[&str]> = tmp_1.iter().map(AsRef::as_ref).collect();

    let combinations = combine(&tmp_2[..]);

    let binary_path = fs::canonicalize(BINARY_DIR)?.join(name);

    let mut results = Vec::with_capacity(combinations.len());

    for combination in &combinations {
        let mut cmd = Command::new(TIME_CMD);
        cmd.arg("-v").arg(&binary_path);

        let mut print_comb = "\t".to_owned();
        for (i, param) in combination.iter().enumerate() {
            let n = config.get_param_name(i)?;
            cmd.arg(format!("--{}", n)).arg(param);
            print_comb += &format!("{}: {}\t", n, param);
        }
        println!("{}", print_comb);

        if let Some(ref command) = config.command {
            cmd.arg(command);
        }

        let output = cmd.output()?;
        let res = BenchmarkResult::new(
            combination,
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        )?;

        let mut data = serde_json::to_string(&res)?;
        data.push('\n');
        results.push(res);

        // store result on disk
        let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let filename = result_dir.join(format!(
            "{}-{}.json",
            combination.join("-"),
            timestamp.as_secs(),
        ));

        fs::write(filename, data)?;
    }

    Ok(results)
}

fn main() {
    // the bencher output-parsing code requires JSON, and an environment
    // variable is the mechanism for enabling JSON-log support
    std::env::set_var("FIL_PROOFS_LOG_JSON", "true");

    let matches = App::new("Rust Proofs Bencher")
        .version("1.0")
        .about("Benchmark all the things")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .default_value("bench.config.toml")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("table")
                .long("table")
                .takes_value(false)
                .help("Print a summary as markdown table"),
        )
        .get_matches();

    let config = matches.value_of("config").unwrap();
    let print_table = matches.is_present("table");

    ::std::process::exit(match run(config, print_table) {
        Ok(_) => 0,
        Err(err) => {
            eprintln!("error: {:?}", err);
            1
        }
    });
}

#[test]
fn test_combine() {
    let input = vec![vec!["1", "2", "3"], vec!["4", "5"]];
    let refs: Vec<&[&str]> = input.iter().map(AsRef::as_ref).collect();
    assert_eq!(
        combine(&refs[..]),
        vec![
            vec!["1", "4"],
            vec!["1", "5"],
            vec!["2", "4"],
            vec!["2", "5"],
            vec!["3", "4"],
            vec!["3", "5"]
        ],
    );
}

#[test]
fn test_time_result_from_str() {
    let res = TimeResult::from_str("
	Command being timed: \"/Users/dignifiedquire/work/filecoin/rust-proofs/target/release/examples/drgporep-vanilla --challenges 1 --size 1 --sloth 0 --m 6 --hasher sha256\"
	User time (seconds): 0.01
	System time (seconds): 0.01
	Percent of CPU this job got: 184%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.01
	Average shared text size (kbytes): 0
	Average unshared data size (kbytes): 0
	Average stack size (kbytes): 0
	Average total size (kbytes): 0
	Maximum resident set size (kbytes): 6932
	Average resident set size (kbytes): 0
	Major (requiring I/O) page faults: 0
	Minor (reclaiming a frame) page faults: 1932
	Voluntary context switches: 0
	Involuntary context switches: 889
	Swaps: 0
	File system inputs: 0
	File system outputs: 0
	Socket messages sent: 0
	Socket messages received: 0
	Signals delivered: 0
	Page size (bytes): 4096
	Exit status: 0
").unwrap();

    assert_eq!(res.command, "/Users/dignifiedquire/work/filecoin/rust-proofs/target/release/examples/drgporep-vanilla --challenges 1 --size 1 --sloth 0 --m 6 --hasher sha256");
    assert_eq!(res.user_time, 0.01);
    assert_eq!(res.swaps, 0);
    assert_eq!(res.involuntary_context_switches, 889);
    assert_eq!(res.cpu, 184);
    assert_eq!(res.elapsed_time, Duration::from_millis(10));
}

#[test]
fn test_log_results_str_json() {
    let res = LogResult::from_str("
{\"msg\":\"constraint system: Groth\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.315918-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:86 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"data_size:  1 kB\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.316948-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:87 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"challenge_count: 1\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.316961-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:88 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"m: 6\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.316970-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:89 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"sloth: 0\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.316978-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:90 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"tree_depth: 5\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.317011-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:91 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"config\"}
{\"msg\":\"reading groth params from cache: \\\"/tmp/filecoin-proofs-cache-multi-challenge merklepor-1024-1-6-0\\\"\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.317046-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:102 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"params\"}
{\"msg\":\"generating verification key\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:19.388725-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:123 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"params\"}
{\"msg\":\"avg_proving_time: 0.213533235 seconds\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:20.480250-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:180 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"stats\"}
{\"msg\":\"avg_verifying_time: 0.003935171 seconds\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:20.480273-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:181 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"stats\"}
{\"msg\":\"params_generation_time: 76.536768ms\",\"level\":\"INFO\",\"ts\":\"2018-12-14T13:57:20.480283-08:00\",\"place\":\"storage-proofs/src/example_helper.rs:182 storage_proofs::example_helper\",\"root\":\"storage-proofs\",\"target\":\"stats\"}

").unwrap();

    assert_eq!(res.config.get("constraint system").unwrap(), "Groth");
    assert_eq!(res.config.get("data_size").unwrap(), "1 kB",);
    assert_eq!(
        res.stats.get("avg_proving_time").unwrap(),
        "0.213533235 seconds"
    );
}
