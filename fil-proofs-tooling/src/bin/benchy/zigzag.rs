use rand::{Rng, SeedableRng, XorShiftRng};
use std::fs::{File, OpenOptions};
use std::time::{Duration, Instant};
use std::u32;

use failure::bail;
use prometheus::{Encoder, IntGaugeVec, TextEncoder};

use bellperson::Circuit;
use chrono::Utc;
use fil_sapling_crypto::jubjub::JubjubBls12;
use lazy_static::lazy_static;
use memmap::MmapMut;
use memmap::MmapOptions;
use paired::bls12_381::Bls12;
use storage_proofs::circuit::metric::MetricCS;
use storage_proofs::circuit::zigzag::ZigZagCompound;
use storage_proofs::compound_proof::{self, CompoundProof};
use storage_proofs::drgporep;
use storage_proofs::drgraph::*;
use storage_proofs::hasher::{Blake2sHasher, Hasher, PedersenHasher, Sha256Hasher};
use storage_proofs::layered_drgporep::{self, ChallengeRequirements, LayerChallenges};
use storage_proofs::porep::PoRep;
use storage_proofs::proof::ProofScheme;
use storage_proofs::zigzag_drgporep::*;

const LABELS: [&str; 8] = [
    "data_size_bytes",
    "m",
    "expansion_degree",
    "sloth_iter",
    "partitions",
    "hasher",
    "samples",
    "layers",
];

lazy_static! {
    static ref REPLICATION_TIME_MS_GAUGE: IntGaugeVec =
        register_int_gauge_vec!("replication_time_ms", "Total replication timea", &LABELS).unwrap();
    static ref REPLICATION_TIME_NS_PER_BYTE_GAUGE: IntGaugeVec = register_int_gauge_vec!(
        "replication_time_ns_per_byte",
        "Replication time per byte",
        &LABELS
    )
    .unwrap();
    static ref VANILLA_PROVING_TIME_US_GAUGE: IntGaugeVec =
        register_int_gauge_vec!("vanilla_proving_time_us", "Vanilla proving time", &LABELS)
            .unwrap();
    static ref VANILLA_VERIFICATION_TIME_US_GAUGE: IntGaugeVec = register_int_gauge_vec!(
        "vanilla_verification_time_us",
        "Vanilla verification time",
        &LABELS
    )
    .unwrap();
    static ref CIRCUIT_NUM_INPUTS_GAUGE: IntGaugeVec = register_int_gauge_vec!(
        "circuit_num_inputs",
        "Number of inputs to the circuit",
        &LABELS
    )
    .unwrap();
    static ref CIRCUIT_NUM_CONSTRAINTS_GAUGE: IntGaugeVec = register_int_gauge_vec!(
        "circuit_num_constraints",
        "Number of constraints of the circuit",
        &LABELS
    )
    .unwrap();
}

fn file_backed_mmap_from_zeroes(n: usize, use_tmp: bool) -> Result<MmapMut, failure::Error> {
    let file: File = if use_tmp {
        tempfile::tempfile().unwrap()
    } else {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(format!("./zigzag-data-{:?}", Utc::now()))
            .unwrap()
    };

    file.set_len(32 * n as u64).unwrap();

    let map = unsafe { MmapOptions::new().map_mut(&file) }?;

    Ok(map)
}

fn dump_proof_bytes<H: Hasher>(
    all_partition_proofs: &[layered_drgporep::Proof<H>],
) -> Result<(), failure::Error> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(format!("./proofs-{:?}", Utc::now()))
        .unwrap();

    serde_json::to_writer(file, all_partition_proofs)?;

    Ok(())
}

#[derive(Debug)]
struct Params {
    samples: usize,
    data_size: usize,
    m: usize,
    expansion_degree: usize,
    sloth_iter: usize,
    layer_challenges: LayerChallenges,
    partitions: usize,
    circuit: bool,
    groth: bool,
    bench: bool,
    extract: bool,
    use_tmp: bool,
    dump_proofs: bool,
    bench_only: bool,
    hasher: String,
}

fn do_the_work<H: 'static>(params: Params, recorder: &Recorder) -> Result<(), failure::Error>
where
    H: Hasher,
{
    println!("zigzag: {:#?}", &params);

    let Params {
        samples,
        data_size,
        m,
        expansion_degree,
        layer_challenges,
        partitions,
        circuit,
        groth,
        bench,
        extract,
        use_tmp,
        dump_proofs,
        bench_only,
        ..
    } = &params;
    let rng = &mut XorShiftRng::from_seed([0x3dbe_6259, 0x8d31_3d76, 0x3237_db17, 0xe5bc_0654]);
    let nodes = data_size / 32;

    let replica_id: H::Domain = rng.gen();
    let sp = layered_drgporep::SetupParams {
        drg: drgporep::DrgParams {
            nodes,
            degree: *m,
            expansion_degree: *expansion_degree,
            seed: new_seed(),
        },
        layer_challenges: layer_challenges.clone(),
    };

    let pp = ZigZagDrgPoRep::<H>::setup(&sp)?;
    let mut total_proving = Duration::new(0, 0);

    let (pub_in, priv_in, d) = if *bench_only {
        (None, None, None)
    } else {
        let mut data = file_backed_mmap_from_zeroes(nodes, *use_tmp)?;

        let start = Instant::now();
        let mut replication_duration = Duration::new(0, 0);

        let (tau, aux) = ZigZagDrgPoRep::<H>::replicate(&pp, &replica_id, &mut data, None)?;
        let pub_inputs = layered_drgporep::PublicInputs::<H::Domain> {
            replica_id,
            seed: None,
            tau: Some(tau.simplify()),
            comm_r_star: tau.comm_r_star,
            k: Some(0),
        };

        let priv_inputs = layered_drgporep::PrivateInputs {
            aux,
            tau: tau.layer_taus,
        };

        replication_duration += start.elapsed();

        let time_per_byte = if *data_size > (u32::MAX as usize) {
            // Duration only supports division by u32, so if data_size (of type usize) is larger,
            // we have to jump through some hoops to get the value we want, which is duration / size.
            // Consider: x = size / max
            //           y = duration / x = duration * max / size
            //           y / max = duration * max / size * max = duration / size
            let x = *data_size as f64 / f64::from(u32::MAX);
            let y = replication_duration / x as u32;
            y / u32::MAX
        } else {
            replication_duration / (*data_size as u32)
        };

        recorder
            .replication_time_ms
            .set(replication_duration.as_millis() as i64);
        recorder
            .replication_time_ns_per_byte
            .set(time_per_byte.as_nanos() as i64);

        println!(
            "Replication: total time: {:.04}s",
            replication_duration.as_millis() as f32 / 1000.
        );
        println!(
            "Replication: time per byte: {:.04}us",
            time_per_byte.as_nanos() as f32 / 1000.
        );

        let start = Instant::now();
        let all_partition_proofs =
            ZigZagDrgPoRep::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, *partitions)?;
        let vanilla_proving = start.elapsed();
        total_proving += vanilla_proving;

        println!(
            "Vanilla proving: {:.04}us",
            vanilla_proving.as_nanos() as f32 / 1000.
        );

        recorder
            .vanilla_proving_time_us
            .set(vanilla_proving.as_micros() as i64);

        if *dump_proofs {
            dump_proof_bytes(&all_partition_proofs)?;
        }

        let mut total_verifying = Duration::new(0, 0);
        for _ in 0..*samples {
            let start = Instant::now();
            let verified = ZigZagDrgPoRep::<H>::verify_all_partitions(
                &pp,
                &pub_inputs,
                &all_partition_proofs,
            )?;
            if !verified {
                panic!("verification failed");
            }

            let elapsed = start.elapsed();
            recorder
                .vanilla_verification_time_us
                .set(elapsed.as_micros() as i64);
            total_verifying += elapsed;
        }

        let verifying_avg = total_verifying / *samples as u32;
        let verifying_avg = f64::from(verifying_avg.subsec_nanos()) / 1_000_000_000f64
            + (verifying_avg.as_secs() as f64);

        println!("Avg verifying: {:.04}s", verifying_avg);

        (Some(pub_inputs), Some(priv_inputs), Some(data))
    };

    if *circuit || *groth || *bench {
        total_proving += do_circuit_work(&pp, pub_in, priv_in, &params, recorder)?;
    }

    if let Some(data) = d {
        if *extract {
            let start = Instant::now();
            let decoded_data = ZigZagDrgPoRep::<H>::extract_all(&pp, &replica_id, &data)?;
            let extracting = start.elapsed();
            assert_eq!(&(*data), decoded_data.as_slice());

            println!("Extracting: {:.04}s", extracting.as_millis() as f32 / 1000.);
        }
    }

    println!(
        "Total proving: {:.04}s",
        total_proving.as_millis() as f32 / 1000.
    );

    Ok(())
}

fn do_circuit_work<H: 'static + Hasher>(
    pp: &<ZigZagDrgPoRep<H> as ProofScheme>::PublicParams,
    pub_in: Option<<ZigZagDrgPoRep<H> as ProofScheme>::PublicInputs>,
    priv_in: Option<<ZigZagDrgPoRep<H> as ProofScheme>::PrivateInputs>,
    params: &Params,
    recorder: &Recorder,
) -> Result<Duration, failure::Error> {
    let mut proving_time = Duration::new(0, 0);
    let Params {
        samples,
        partitions,
        circuit,
        groth,
        bench,
        ..
    } = params;

    let engine_params = JubjubBls12::new();
    let compound_public_params = compound_proof::PublicParams {
        vanilla_params: pp.clone(),
        engine_params: &engine_params,
        partitions: Some(*partitions),
    };

    if *bench || *circuit {
        println!("generating blank metric circuit");
        let mut cs = MetricCS::<Bls12>::new();
        ZigZagCompound::blank_circuit(&pp, &engine_params).synthesize(&mut cs)?;

        println!("circuit_num_inputs: {}", cs.num_inputs());
        println!("circuit_num_constraints: {}", cs.num_constraints());

        recorder.circuit_num_inputs.set(cs.num_inputs() as i64);
        recorder
            .circuit_num_constraints
            .set(cs.num_constraints() as i64);
        if *circuit {
            println!("{}", cs.pretty_print());
        }
    }

    if *groth {
        let pub_inputs = pub_in.expect("missing public inputs");
        let priv_inputs = priv_in.expect("missing private inputs");

        // TODO: The time measured for Groth proving also includes parameter loading (which can be long)
        // and vanilla proving, which may also be.
        // For now, analysis should note and subtract out these times.
        // We should implement a method of CompoundProof, which will skip vanilla proving.
        // We should also allow the serialized vanilla proofs to be passed (as a file) to the example
        // and skip replication/vanilla-proving entirely.
        let gparams =
            ZigZagCompound::groth_params(&compound_public_params.vanilla_params, &engine_params)?;

        let multi_proof = {
            let start = Instant::now();
            let result = ZigZagCompound::prove(
                &compound_public_params,
                &pub_inputs,
                &priv_inputs,
                &gparams,
            )?;
            let groth_proving = start.elapsed();
            proving_time += groth_proving;
            result
        };

        let verified = {
            let mut total_groth_verifying = Duration::new(0, 0);
            let mut result = true;
            for _ in 0..*samples {
                let start = Instant::now();
                let cur_result = result;
                ZigZagCompound::verify(
                    &compound_public_params,
                    &pub_inputs,
                    &multi_proof,
                    &ChallengeRequirements {
                        minimum_challenges: 1,
                    },
                )?;
                // If one verification fails, result becomes permanently false.
                result = result && cur_result;
                total_groth_verifying += start.elapsed();
            }
            let avg_groth_verifying = total_groth_verifying / *samples as u32;
            println!(
                "Avg groth verifying: {:.04}s",
                avg_groth_verifying.as_millis() as f32 / 1000.
            );
            result
        };
        assert!(verified);
    }

    Ok(proving_time)
}

type IntGauge = prometheus::core::GenericGauge<prometheus::core::AtomicI64>;

struct Recorder {
    pub replication_time_ms: IntGauge,
    pub replication_time_ns_per_byte: IntGauge,
    pub vanilla_proving_time_us: IntGauge,
    pub vanilla_verification_time_us: IntGauge,
    pub circuit_num_inputs: IntGauge,
    pub circuit_num_constraints: IntGauge,
}

impl Recorder {
    pub fn from_params(params: &Params) -> Self {
        let l0 = format!("{}", params.data_size);
        let l1 = format!("{}", params.m);
        let l2 = format!("{}", params.expansion_degree);
        let l3 = format!("{}", params.sloth_iter);
        let l4 = format!("{}", params.partitions);
        let l5 = params.hasher.clone();
        let l6 = format!("{}", params.samples);
        let l7 = format!("{}", params.layer_challenges.layers());

        let labels = [
            l0.as_str(),
            l1.as_str(),
            l2.as_str(),
            l3.as_str(),
            l4.as_str(),
            l5.as_str(),
            l6.as_str(),
            l7.as_str(),
        ];

        Recorder {
            replication_time_ms: REPLICATION_TIME_MS_GAUGE.with_label_values(&labels[..]),
            replication_time_ns_per_byte: REPLICATION_TIME_NS_PER_BYTE_GAUGE
                .with_label_values(&labels[..]),
            vanilla_proving_time_us: VANILLA_PROVING_TIME_US_GAUGE.with_label_values(&labels[..]),
            vanilla_verification_time_us: VANILLA_VERIFICATION_TIME_US_GAUGE
                .with_label_values(&labels[..]),
            circuit_num_inputs: CIRCUIT_NUM_INPUTS_GAUGE.with_label_values(&labels[..]),
            circuit_num_constraints: CIRCUIT_NUM_CONSTRAINTS_GAUGE.with_label_values(&labels[..]),
        }
    }

    /// Print all results to stdout
    pub fn print(&self) {
        // Gather the metrics.
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        // Output to the standard output.
        println!("{}", String::from_utf8(buffer).unwrap());
    }

    /// Pushes the data to the prometheus push server.
    pub fn push(&self) {
        let address = "127.0.0.1:9091";

        let metric_families = prometheus::gather();
        prometheus::push_metrics(
            "filbase-zigzag-bench",
            labels! { "why".to_owned() => "are you here?".to_owned(), },
            &address,
            metric_families,
            None,
        )
        .expect("failed to push")
    }
}

pub struct RunOpts {
    pub bench: bool,
    pub bench_only: bool,
    pub challenges: usize,
    pub circuit: bool,
    pub dump: bool,
    pub exp: usize,
    pub extract: bool,
    pub groth: bool,
    pub hasher: String,
    pub layers: usize,
    pub m: usize,
    pub no_bench: bool,
    pub no_tmp: bool,
    pub partitions: usize,
    pub push_prometheus: bool,
    pub size: usize,
    pub sloth: usize,
    pub taper: f64,
    pub taper_layers: usize,
}

pub fn run(opts: RunOpts) -> Result<(), failure::Error> {
    let layer_challenges = if opts.taper == 0.0 {
        LayerChallenges::new_fixed(opts.layers, opts.challenges)
    } else {
        LayerChallenges::new_tapered(opts.layers, opts.challenges, opts.taper_layers, opts.taper)
    };

    let params = Params {
        layer_challenges,
        data_size: opts.size * 1024,
        m: opts.m,
        expansion_degree: opts.exp,
        sloth_iter: opts.sloth,
        partitions: opts.partitions,
        use_tmp: !opts.no_tmp,
        dump_proofs: opts.dump,
        groth: opts.groth,
        bench: !opts.no_bench && opts.bench,
        bench_only: opts.bench_only,
        circuit: opts.circuit,
        extract: opts.extract,
        hasher: opts.hasher,
        samples: 5,
    };

    let recorder = Recorder::from_params(&params);

    match params.hasher.as_ref() {
        "pedersen" => do_the_work::<PedersenHasher>(params, &recorder)?,
        "sha256" => do_the_work::<Sha256Hasher>(params, &recorder)?,
        "blake2s" => do_the_work::<Blake2sHasher>(params, &recorder)?,
        _ => bail!("invalid hasher: {}", params.hasher),
    }

    recorder.print();

    if opts.push_prometheus {
        recorder.push();
    }

    Ok(())
}
