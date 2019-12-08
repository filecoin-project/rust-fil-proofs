use std::fs::File;
use std::io::stderr;
use std::path::Path;
use std::time::{Duration, Instant};

use bellperson::groth16::*;
use bellperson::Circuit;
use clap::{self, value_t, App, Arg, SubCommand};
use fil_sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};
use log::info;
use paired::bls12_381::Bls12;
use pbr::ProgressBar;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

use crate::circuit::bench::BenchCS;
use crate::circuit::test::TestConstraintSystem;
use crate::crypto::pedersen::JJ_PARAMS;

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
        .expect("Failed to parse `number` as `u64`")
        * 1_f64;
    let unit = units[exponent as usize];
    format!("{}{} {}", negative, pretty_bytes, unit)
}

/// Generate a unique cache path, based on the inputs.
fn get_cache_path(name: &str, data_size: usize, challenge_count: usize, m: usize) -> String {
    format!(
        "/tmp/filecoin-proofs-cache-{}-{}-{}-{}",
        name.to_ascii_lowercase(),
        data_size,
        challenge_count,
        m,
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
pub trait Example<'a, C: Circuit<Bls12>>: Default {
    /// The actual work.
    fn work_groth(&mut self, typ: CSType, data_size: usize, challenge_count: usize, m: usize) {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!("constraint system: {:?}", typ);
        info!("data_size:  {}", prettyb(data_size));
        info!("challenge_count: {}", challenge_count);
        info!("m: {}", m);
        info!("tree_depth: {}", tree_depth);

        let start = Instant::now();
        let mut param_duration = Duration::new(0, 0);

        let name = Self::name();

        // caching
        let p = get_cache_path(&name, data_size, challenge_count, m);
        let cache_path = Path::new(&p);
        let groth_params: Parameters<Bls12> = if cache_path.exists() {
            info!("reading groth params from cache: {:?}", cache_path);
            let f = File::open(&cache_path).expect("failed to read cache");
            Parameters::read(&f, false).expect("failed to read cached params")
        } else {
            info!("generating new groth params");
            let p = self.generate_groth_params(rng, &JJ_PARAMS, tree_depth, challenge_count, m);
            info!("writing params to cache: {:?}", cache_path);

            let mut f = File::create(&cache_path).expect("faild to open cache file");
            p.write(&mut f).expect("failed to write params to cache");

            p
        };

        info!("generating verification key");
        let pvk = prepare_verifying_key(&groth_params.vk);

        param_duration += start.elapsed();

        let samples = Self::samples() as u32;

        let mut proof_vec = vec![];
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        let mut pb = ProgressBar::on(stderr(), u64::from(samples * 2));

        for _ in 0..samples {
            proof_vec.truncate(0);

            // -- create proof

            let start = Instant::now();
            let proof = self.create_proof(
                rng,
                &JJ_PARAMS,
                &groth_params,
                tree_depth,
                challenge_count,
                leaves,
                m,
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

        info!("avg_proving_time: {:?} seconds", proving_avg);
        info!("avg_verifying_time: {:?} seconds", verifying_avg);
        info!("params_generation_time: {:?}", param_duration);
    }

    fn work_bench(&mut self, typ: CSType, data_size: usize, challenge_count: usize, m: usize) {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!("constraint system: {:?}", typ);
        info!("data_size:  {}", prettyb(data_size));
        info!("challenge_count: {}", challenge_count);
        info!("m: {}", m);
        info!("tree_depth: {}", tree_depth);

        // need more samples as this is a faster operation
        let samples = (Self::samples() * 10) as u32;

        let mut total_synth = Duration::new(0, 0);

        let mut pb = ProgressBar::on(stderr(), u64::from(samples));

        info!(
            "constraints: {}",
            self.get_num_constraints(rng, &JJ_PARAMS, tree_depth, challenge_count, leaves, m)
        );

        for _ in 0..samples {
            // -- create proof

            let start = Instant::now();
            let c = self.create_circuit(rng, &JJ_PARAMS, tree_depth, challenge_count, leaves, m);
            let mut cs = BenchCS::<Bls12>::new();
            c.synthesize(&mut cs).expect("failed to synthesize circuit");

            total_synth += start.elapsed();
            pb.inc();
        }

        // -- print statistics

        let synth_avg = total_synth / samples;
        let synth_avg =
            f64::from(synth_avg.subsec_nanos()) / 1_000_000_000f64 + (synth_avg.as_secs() as f64);

        info!("avg_synthesize_time: {:?} seconds", synth_avg);
    }

    fn work_circuit(&mut self, typ: CSType, data_size: usize, challenge_count: usize, m: usize) {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!("constraint system: {:?}", typ);
        info!("data_size:  {}", prettyb(data_size));
        info!("challenge_count: {}", challenge_count);
        info!("m: {}", m);
        info!("tree_depth: {}", tree_depth);

        let c = self.create_circuit(rng, &JJ_PARAMS, tree_depth, challenge_count, leaves, m);
        let mut cs = TestConstraintSystem::<Bls12>::new();
        c.synthesize(&mut cs).expect("failed to synthesize circuit");
        assert!(cs.is_satisfied(), "constraints not satisfied");

        println!("{}", cs.pretty_print());
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

        let (data_size, challenge_count, m, typ) = {
            let matches = instance.clap();

            let data_size = value_t!(matches, "size", usize)
                .map(|size| size * 1024)
                .expect("Failed to parse `size` CLI arg as `usize`");
            let challenge_count = value_t!(matches, "challenges", usize)
                .expect("Failed to parse `challenges` CLI arg as `usize`");
            let m = value_t!(matches, "m", usize).expect("Failed to parse `m` CLI arg as `usize`");
            let typ = match matches.subcommand_name() {
                Some("groth") => CSType::Groth,
                Some("bench") => CSType::Bench,
                Some("circuit") => CSType::Circuit,
                _ => panic!("please select a valid subcommand"),
            };

            (data_size, challenge_count, m, typ)
        };

        match typ {
            CSType::Groth => instance.work_groth(typ, data_size, challenge_count, m),
            CSType::Bench => instance.work_bench(typ, data_size, challenge_count, m),
            CSType::Circuit => instance.work_circuit(typ, data_size, challenge_count, m),
        }
    }

    /// The name of the application. Used for identifying caches.
    fn name() -> String;

    /// Generate groth parameters
    fn generate_groth_params<R: Rng>(
        &mut self,
        _: &mut R,
        _: &'a <Bls12 as JubjubEngine>::Params,
        _: usize,
        _: usize,
        _: usize,
    ) -> Parameters<Bls12>;

    /// How many samples should be taken when proofing and verifying
    fn samples() -> usize;

    /// Create a new random proof
    #[allow(clippy::too_many_arguments)]
    fn create_circuit<R: Rng>(
        &mut self,
        _: &mut R,
        _: &'a <Bls12 as JubjubEngine>::Params,
        _: usize,
        _: usize,
        _: usize,
        _: usize,
    ) -> C;

    #[allow(clippy::too_many_arguments)]
    fn create_proof<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &'a <Bls12 as JubjubEngine>::Params,
        groth_params: &Parameters<Bls12>,
        tree_depth: usize,
        challenge_count: usize,
        leaves: usize,
        m: usize,
    ) -> Proof<Bls12> {
        let c = self.create_circuit(rng, engine_params, tree_depth, challenge_count, leaves, m);
        create_random_proof(c, groth_params, rng).expect("failed to create proof")
    }

    /// Verify the given proof, return `None` if not implemented.
    fn verify_proof(&mut self, _: &Proof<Bls12>, _: &PreparedVerifyingKey<Bls12>) -> Option<bool>;

    /// Get the number of constraints of the circuit
    #[allow(clippy::too_many_arguments)]
    fn get_num_constraints<R: Rng>(
        &mut self,
        rng: &mut R,
        engine_params: &'a JubjubBls12,
        tree_depth: usize,
        challenge_count: usize,
        leaves: usize,
        m: usize,
    ) -> usize {
        let c = self.create_circuit(rng, engine_params, tree_depth, challenge_count, leaves, m);

        let mut cs = BenchCS::<Bls12>::new();
        c.synthesize(&mut cs).expect("failed to synthesize circuit");

        cs.num_constraints()
    }
}
