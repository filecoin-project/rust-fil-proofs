use bellman::groth16::*;
use clap::{App, Arg};
use colored::*;
use env_logger;
use indicatif::{ProgressBar, ProgressStyle};
use log::{Level, LevelFilter};
use rand::{Rng, SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::JubjubEngine;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

fn get_cache_path(name: &str, data_size: usize, challenge_count: usize, m: usize) -> String {
    format!(
        "/tmp/filecoin-proofs-cache-{}-{}-{}-{}",
        name.to_ascii_lowercase(),
        data_size,
        challenge_count,
        m
    )
}

pub trait Example<E: JubjubEngine>: Default {
    fn do_the_work(&mut self, data_size: usize, challenge_count: usize, m: usize) {
        let engine_params = Self::generate_engine_params();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let lambda = 32;
        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!(target: "config", "data size:  {} bytes", data_size);
        info!(target: "config", "m: {}", m);
        info!(target: "config", "tree depth: {}", tree_depth);

        let start = Instant::now();
        let mut param_duration = Duration::new(0, 0);

        let name = Self::name();

        // caching
        let p = get_cache_path(&name, data_size, challenge_count, m);
        let cache_path = Path::new(&p);
        let groth_params: Parameters<E> = if cache_path.exists() {
            info!(target: "params", "reading groth params from cache: {:?}", cache_path);
            let mut f = File::open(&cache_path).expect("failed to read cache");
            Parameters::read(&f, false).expect("failed to read cached paramse")
        } else {
            info!(target: "params", "generating new groth params");
            let p = self.generate_groth_params(
                rng,
                &engine_params,
                tree_depth,
                challenge_count,
                lambda,
                m,
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

        let pb = ProgressBar::new(u64::from(samples * 2));
        pb.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
                )
                .progress_chars("#>-"),
        );

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
            );
            proof
                .write(&mut proof_vec)
                .expect("failed to serialize proof");
            total_proving += start.elapsed();
            pb.inc(1);

            // -- verify proof

            let start = Instant::now();

            if let Some(is_valid) = self.verify_proof(&proof, &pvk) {
                assert!(is_valid, "failed to verify proof");
            }

            total_verifying += start.elapsed();
            pb.inc(1);
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

    fn main() {
        let mut instance = Self::default();
        // set default logging level to info

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

        let matches = App::new(Self::name())
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
                    .default_value("6")
                    .takes_value(true),
            )
            .get_matches();

        let data_size = value_t!(matches, "size", usize).unwrap() * 1024;
        let challenge_count = value_t!(matches, "challenges", usize).unwrap();
        let m = value_t!(matches, "m", usize).unwrap();

        instance.do_the_work(data_size, challenge_count, m);
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
    ) -> Proof<E>;

    /// Verify the given proof, return `None` if not implemented.
    fn verify_proof(&mut self, &Proof<E>, &PreparedVerifyingKey<E>) -> Option<bool>;
}
