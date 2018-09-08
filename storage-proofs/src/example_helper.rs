use bellman::groth16::*;
use clap::{self, App, Arg, SubCommand};
use colored::*;
use env_logger;
use log::{Level, LevelFilter};
use pbr::ProgressBar;
use rand::{Rng, SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::JubjubEngine;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

pub fn prettyb(num: usize) -> String {
    let num = num as f64;
    let negative = if num.is_sign_positive() { "" } else { "-" };
    let num = num.abs();
    let units = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    if num < 1_f64 {
        return format!("{}{} {}", negative, num, "B");
    }
    let delimiter = 1024_f64;
    let exponent = ::std::cmp::min(
        (num.ln() / delimiter.ln()).floor() as i32,
        (units.len() - 1) as i32,
    );
    let pretty_bytes = format!("{:.2}", num / delimiter.powi(exponent))
        .parse::<f64>()
        .unwrap() * 1_f64;
    let unit = units[exponent as usize];
    format!("{}{} {}", negative, pretty_bytes, unit)
}

pub fn init_logger() {
    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(LevelFilter::Info)
        .format(|buf, record| {
            let ts = buf.timestamp();
            let level = match record.level() {
                Level::Trace => "TRACE".purple(),
                Level::Debug => "DEBUG".blue(),
                Level::Info => "INFO ".green(),
                Level::Warn => "WARN ".yellow(),
                Level::Error => "ERROR".red(),
            };
            writeln!(
                buf,
                "{} {} {} > {}",
                ts,
                level,
                record.target(),
                record.args()
            )
        })
        .init();
}

/// Generate a unique cache path, based on the inputs.
fn get_cache_path(
    name: &str,
    data_size: usize,
    challenge_count: usize,
    m: usize,
    sloth: usize,
) -> String {
    format!(
        "/tmp/filecoin-proofs-cache-{}-{}-{}-{}-{}",
        name.to_ascii_lowercase(),
        data_size,
        challenge_count,
        m,
        sloth,
    )
}

/// The available circuit types for benchmarking.
#[derive(Debug)]
pub enum CSType {
    Groth,
    Bench,
    Circuit,
}

/// A trait that makes it easy to implement "Examples". These are really tunable benchmarking CLI tools.
pub trait Example<E: JubjubEngine>: Default {
    /// The actual work.
    fn work_groth(
        &mut self,
        typ: CSType,
        data_size: usize,
        challenge_count: usize,
        m: usize,
        sloth_iter: usize,
    ) {
        let engine_params = Self::generate_engine_params();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!(target: "config", "constraint system: {:?}", typ);
        info!(target: "config", "data size:  {}", prettyb(data_size));
        info!(target: "config", "challenge count: {}", challenge_count);
        info!(target: "config", "m: {}", m);
        info!(target: "config", "sloth: {}", sloth_iter);
        info!(target: "config", "tree depth: {}", tree_depth);

        let start = Instant::now();
        let mut param_duration = Duration::new(0, 0);

        let name = Self::name();

        // caching
        let p = get_cache_path(&name, data_size, challenge_count, m, sloth_iter);
        let cache_path = Path::new(&p);
        let groth_params: Parameters<E> = if cache_path.exists() {
            info!(target: "params", "reading groth params from cache: {:?}", cache_path);
            let mut f = File::open(&cache_path).expect("failed to read cache");
            Parameters::read(&f, false).expect("failed to read cached params")
        } else {
            info!(target: "params", "generating new groth params");
            let p = self.generate_groth_params(
                rng,
                &engine_params,
                tree_depth,
                challenge_count,
                lambda,
                m,
                sloth_iter,
            );
            info!(target: "params", "writing params to cache: {:?}", cache_path);

            let mut f = File::create(&cache_path).expect("faild to open cache file");
            p.write(&mut f).expect("failed to write params to cache");

            p
        };

        info!(target: "params", "generating verification key");
        let pvk = prepare_verifying_key(&groth_params.vk);

        param_duration += start.elapsed();

        let samples = Self::samples() as u32;

        let mut proof_vec = vec![];
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        let mut pb = ProgressBar::new(u64::from(samples * 2));

        for _ in 0..samples {
            proof_vec.truncate(0);

            // -- create proof

            let start = Instant::now();
            let proof = self.create_proof(
                rng,
                &engine_params,
                &groth_params,
                tree_depth,
                challenge_count,
                leaves,
                lambda,
                m,
                sloth_iter,
            );
            proof
                .write(&mut proof_vec)
                .expect("failed to serialize proof");
            total_proving += start.elapsed();
            pb.inc();

            // -- verify proof

            let start = Instant::now();

            if let Some(is_valid) = self.verify_proof(&proof, &pvk) {
                assert!(is_valid, "failed to verify proof");
            }

            total_verifying += start.elapsed();
            pb.inc();
        }

        // -- print statistics

        let proving_avg = total_proving / samples;
        let proving_avg = f64::from(proving_avg.subsec_nanos()) / 1_000_000_000f64
            + (proving_avg.as_secs() as f64);

        let verifying_avg = total_verifying / samples;
        let verifying_avg = f64::from(verifying_avg.subsec_nanos()) / 1_000_000_000f64
            + (verifying_avg.as_secs() as f64);

        info!(target: "stats", "Average proving time: {:?} seconds", proving_avg);
        info!(target: "stats", "Average verifying time: {:?} seconds", verifying_avg);
        info!(target: "stats", "Params generation time: {:?}", param_duration);

        // need this, as the last item doesn't get flushed to the console sometimes
        info!(".")
    }

    fn work_circuit(
        &mut self,
        typ: CSType,
        data_size: usize,
        challenge_count: usize,
        m: usize,
        sloth_iter: usize,
    ) {
        let engine_params = Self::generate_engine_params();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!(target: "config", "constraint system: {:?}", typ);
        info!(target: "config", "data size:  {}", prettyb(data_size));
        info!(target: "config", "challenge count: {}", challenge_count);
        info!(target: "config", "m: {}", m);
        info!(target: "config", "sloth: {}", sloth_iter);
        info!(target: "config", "tree depth: {}", tree_depth);

        self.pretty_print(
            rng,
            &engine_params,
            tree_depth,
            challenge_count,
            leaves,
            lambda,
            m,
            sloth_iter,
        );
    }

    fn work_bench(
        &mut self,
        typ: CSType,
        data_size: usize,
        challenge_count: usize,
        m: usize,
        sloth_iter: usize,
    ) {
        let engine_params = Self::generate_engine_params();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!(target: "config", "constraint system: {:?}", typ);
        info!(target: "config", "data size:  {}", prettyb(data_size));
        info!(target: "config", "challenge count: {}", challenge_count);
        info!(target: "config", "m: {}", m);
        info!(target: "config", "sloth: {}", sloth_iter);
        info!(target: "config", "tree depth: {}", tree_depth);

        // need more samples as this is a faster operation
        let samples = (Self::samples() * 10) as u32;

        let mut total_synth = Duration::new(0, 0);

        let mut pb = ProgressBar::new(u64::from(samples));

        info!(
            target: "stats",
            "Number of constraints: {}",
            self.get_num_constraints(
                rng,
                &engine_params,
                tree_depth,
                challenge_count,
                leaves,
                lambda,
                m,
                sloth_iter,
            )
        );

        for _ in 0..samples {
            // -- create proof

            let start = Instant::now();
            self.create_bench(
                rng,
                &engine_params,
                tree_depth,
                challenge_count,
                leaves,
                lambda,
                m,
                sloth_iter,
            );
            total_synth += start.elapsed();
            pb.inc();
        }

        // -- print statistics

        let synth_avg = total_synth / samples;
        let synth_avg =
            f64::from(synth_avg.subsec_nanos()) / 1_000_000_000f64 + (synth_avg.as_secs() as f64);

        info!(target: "stats", "Average synthesize time: {:?} seconds", synth_avg);

        // need this, as the last item doesn't get flushed to the console sometimes
        info!(".")
    }

    fn clap(&self) -> clap::ArgMatches {
        App::new(stringify!($name))
            .version("1.0")
            .arg(
                Arg::with_name("size")
                    .required(true)
                    .long("size")
                    .help("The data size in KB")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("challenges")
                    .long("challenges")
                    .help("How many challenges to execute, defaults to 1")
                    .default_value("1")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("m")
                    .help("The size of m")
                    .long("m")
                    .default_value("6")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("sloth")
                    .help("The number of sloth iterations, defaults to 1")
                    .long("sloth")
                    .default_value("1")
                    .takes_value(true),
            )
            .subcommand(
                SubCommand::with_name("groth")
                    .about("execute circuits using groth constraint system"),
            )
            .subcommand(
                SubCommand::with_name("bench")
                    .about("execute circuits using a minimal benchmarking constraint"),
            )
            .subcommand(SubCommand::with_name("circuit").about("print the constraint system"))
            .get_matches()
    }

    fn main() {
        let mut instance = Self::default();
        // set default logging level to info

        init_logger();

        let (data_size, challenge_count, m, sloth_iter, typ) = {
            let matches = instance.clap();

            let data_size = value_t!(matches, "size", usize).unwrap() * 1024;
            let challenge_count = value_t!(matches, "challenges", usize).unwrap();
            let m = value_t!(matches, "m", usize).unwrap();
            let sloth_iter = value_t!(matches, "sloth", usize).unwrap();

            let typ = match matches.subcommand_name() {
                Some("groth") => CSType::Groth,
                Some("bench") => CSType::Bench,
                Some("circuit") => CSType::Circuit,
                _ => panic!("please select a valid subcommand"),
            };

            (data_size, challenge_count, m, sloth_iter, typ)
        };

        match typ {
            CSType::Groth => instance.work_groth(typ, data_size, challenge_count, m, sloth_iter),
            CSType::Bench => instance.work_bench(typ, data_size, challenge_count, m, sloth_iter),
            CSType::Circuit => {
                instance.work_circuit(typ, data_size, challenge_count, m, sloth_iter)
            }
        }
    }

    /// The name of the application. Used for identifying caches.
    fn name() -> String;

    /// Generate engine params
    fn generate_engine_params() -> E::Params;

    /// Generate groth parameters
    fn generate_groth_params<R: Rng>(
        &mut self,
        &mut R,
        &E::Params,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) -> Parameters<E>;

    /// How many samples should be taken when proofing and verifying
    fn samples() -> usize;

    /// Create a new random proof
    fn create_proof<R: Rng>(
        &mut self,
        &mut R,
        &E::Params,
        &Parameters<E>,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) -> Proof<E>;

    /// Verify the given proof, return `None` if not implemented.
    fn verify_proof(&mut self, &Proof<E>, &PreparedVerifyingKey<E>) -> Option<bool>;

    /// Create a new bench
    fn create_bench<R: Rng>(
        &mut self,
        &mut R,
        &E::Params,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    );

    fn pretty_print<R: Rng>(
        &mut self,
        &mut R,
        &E::Params,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    );

    /// Get the number of constraitns of the circuit
    fn get_num_constraints<R: Rng>(
        &mut self,
        &mut R,
        &E::Params,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) -> usize;
}
