use std::fs::File;
use std::io::stderr;
use std::path::Path;
use std::time::{Duration, Instant};

use bellman::groth16::*;
use bellman::Circuit;
use clap::{self, App, Arg, SubCommand};
use pairing::bls12_381::Bls12;
use pbr::ProgressBar;
use rand::{Rng, SeedableRng, XorShiftRng};
use sapling_crypto::jubjub::{JubjubBls12, JubjubEngine};

use crate::circuit::bench::BenchCS;
use crate::circuit::test::TestConstraintSystem;

use crate::SP_LOG;

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
        .unwrap()
        * 1_f64;
    let unit = units[exponent as usize];
    format!("{}{} {}", negative, pretty_bytes, unit)
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

lazy_static! {
    static ref JUBJUB_BLS_PARAMS: JubjubBls12 = JubjubBls12::new();
}

/// A trait that makes it easy to implement "Examples". These are really tunable benchmarking CLI tools.
pub trait Example<'a, C: Circuit<Bls12>>: Default {
    /// The actual work.
    fn work_groth(
        &mut self,
        typ: CSType,
        data_size: usize,
        challenge_count: usize,
        m: usize,
        sloth_iter: usize,
    ) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!(SP_LOG, "constraint system: {:?}", typ; "target" => "config");
        info!(SP_LOG, "data_size:  {}", prettyb(data_size); "target" => "config");
        info!(SP_LOG, "challenge_count: {}", challenge_count; "target" => "config");
        info!(SP_LOG, "m: {}", m; "target" => "config");
        info!(SP_LOG, "sloth: {}", sloth_iter; "target" => "config");
        info!(SP_LOG, "tree_depth: {}", tree_depth; "target" => "config");

        let start = Instant::now();
        let mut param_duration = Duration::new(0, 0);

        let name = Self::name();

        // caching
        let p = get_cache_path(&name, data_size, challenge_count, m, sloth_iter);
        let cache_path = Path::new(&p);
        let groth_params: Parameters<Bls12> = if cache_path.exists() {
            info!(SP_LOG, "reading groth params from cache: {:?}", cache_path; "target" => "params");
            let f = File::open(&cache_path).expect("failed to read cache");
            Parameters::read(&f, false).expect("failed to read cached params")
        } else {
            info!(SP_LOG, "generating new groth params"; "target" => "params");
            let p = self.generate_groth_params(
                rng,
                &JUBJUB_BLS_PARAMS,
                tree_depth,
                challenge_count,
                m,
                sloth_iter,
            );
            info!(SP_LOG, "writing params to cache: {:?}", cache_path; "target" => "params");

            let mut f = File::create(&cache_path).expect("faild to open cache file");
            p.write(&mut f).expect("failed to write params to cache");

            p
        };

        info!(SP_LOG, "generating verification key"; "target" => "params");
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
                &JUBJUB_BLS_PARAMS,
                &groth_params,
                tree_depth,
                challenge_count,
                leaves,
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

        info!(SP_LOG, "avg_proving_time: {:?} seconds", proving_avg; "target" => "stats");
        info!(SP_LOG, "avg_verifying_time: {:?} seconds", verifying_avg; "target" => "stats");
        info!(SP_LOG, "params_generation_time: {:?}", param_duration; "target" => "stats");
    }

    fn work_bench(
        &mut self,
        typ: CSType,
        data_size: usize,
        challenge_count: usize,
        m: usize,
        sloth_iter: usize,
    ) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!(SP_LOG, "constraint system: {:?}", typ; "target" => "config");
        info!(SP_LOG, "data_size:  {}", prettyb(data_size); "target" => "config");
        info!(SP_LOG, "challenge_count: {}", challenge_count; "target" => "config");
        info!(SP_LOG, "m: {}", m; "target" => "config");
        info!(SP_LOG, "sloth: {}", sloth_iter; "target" => "config");
        info!(SP_LOG, "tree_depth: {}", tree_depth; "target" => "config");

        // need more samples as this is a faster operation
        let samples = (Self::samples() * 10) as u32;

        let mut total_synth = Duration::new(0, 0);

        let mut pb = ProgressBar::on(stderr(), u64::from(samples));

        info!(
            SP_LOG,
            "constraints: {}",
            self.get_num_constraints(
                rng,
                &JUBJUB_BLS_PARAMS,
                tree_depth,
                challenge_count,
                leaves,
                m,
                sloth_iter,
            )
        );

        for _ in 0..samples {
            // -- create proof

            let start = Instant::now();
            let c = self.create_circuit(
                rng,
                &JUBJUB_BLS_PARAMS,
                tree_depth,
                challenge_count,
                leaves,
                m,
                sloth_iter,
            );
            let mut cs = BenchCS::<Bls12>::new();
            c.synthesize(&mut cs).expect("failed to synthesize circuit");

            total_synth += start.elapsed();
            pb.inc();
        }

        // -- print statistics

        let synth_avg = total_synth / samples;
        let synth_avg =
            f64::from(synth_avg.subsec_nanos()) / 1_000_000_000f64 + (synth_avg.as_secs() as f64);

        info!(SP_LOG, "avg_synthesize_time: {:?} seconds", synth_avg; "target" => "stats");
    }

    fn work_circuit(
        &mut self,
        typ: CSType,
        data_size: usize,
        challenge_count: usize,
        m: usize,
        sloth_iter: usize,
    ) {
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let leaves = data_size / 32;
        let tree_depth = (leaves as f64).log2().ceil() as usize;

        info!(SP_LOG, "constraint system: {:?}", typ; "target" => "config");
        info!(SP_LOG, "data_size:  {}", prettyb(data_size); "target" => "config");
        info!(SP_LOG, "challenge_count: {}", challenge_count; "target" => "config");
        info!(SP_LOG, "m: {}", m; "target" => "config");
        info!(SP_LOG, "sloth: {}", sloth_iter; "target" => "config");
        info!(SP_LOG, "tree_depth: {}", tree_depth; "target" => "config");

        let c = self.create_circuit(
            rng,
            &JUBJUB_BLS_PARAMS,
            tree_depth,
            challenge_count,
            leaves,
            m,
            sloth_iter,
        );
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

    /// Generate groth parameters
    fn generate_groth_params<R: Rng>(
        &mut self,
        _: &mut R,
        _: &'a <Bls12 as JubjubEngine>::Params,
        _: usize,
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
        sloth_iter: usize,
    ) -> Proof<Bls12> {
        let c = self.create_circuit(
            rng,
            engine_params,
            tree_depth,
            challenge_count,
            leaves,
            m,
            sloth_iter,
        );
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
        sloth_iter: usize,
    ) -> usize {
        let c = self.create_circuit(
            rng,
            engine_params,
            tree_depth,
            challenge_count,
            leaves,
            m,
            sloth_iter,
        );

        let mut cs = BenchCS::<Bls12>::new();
        c.synthesize(&mut cs).expect("failed to synthesize circuit");

        cs.num_constraints()
    }
}
