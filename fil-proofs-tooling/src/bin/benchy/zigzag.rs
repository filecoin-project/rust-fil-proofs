use std::fs::{File, OpenOptions};
use std::time::{Duration, Instant};
use std::{io, u32};

use bellperson::Circuit;
use chrono::Utc;
use failure::bail;
use fil_sapling_crypto::jubjub::JubjubBls12;
use memmap::MmapMut;
use memmap::MmapOptions;
use paired::bls12_381::Bls12;
use rand::{Rng, SeedableRng, XorShiftRng};

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

#[derive(Clone, Debug)]
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

impl From<Params> for Inputs {
    fn from(p: Params) -> Self {
        Inputs {
            data_size: p.data_size,
            m: p.m,
            expansion_degree: p.expansion_degree,
            sloth_iter: p.sloth_iter,
            partitions: p.partitions,
            hasher: p.hasher.clone(),
            samples: p.samples,
            layers: p.layer_challenges.layers(),
        }
    }
}

fn generate_report<H: 'static>(params: Params) -> Result<Report, failure::Error>
where
    H: Hasher,
{
    let mut report = Report {
        inputs: Inputs::from(params.clone()),
        outputs: Default::default(),
    };

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

        report.outputs.replication_time_ms = Some(replication_duration.as_millis() as u64);
        report.outputs.replication_time_ns_per_byte = Some(time_per_byte.as_nanos() as u64);

        let start = Instant::now();
        let all_partition_proofs =
            ZigZagDrgPoRep::<H>::prove_all_partitions(&pp, &pub_inputs, &priv_inputs, *partitions)?;
        let vanilla_proving = start.elapsed();
        total_proving += vanilla_proving;

        report.outputs.vanilla_proving_time_us = Some(vanilla_proving.as_micros() as u64);

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
            report.outputs.vanilla_verification_time_us = Some(elapsed.as_micros() as u64);
            total_verifying += elapsed;
        }

        let verifying_avg = total_verifying / *samples as u32;
        let verifying_avg = f64::from(verifying_avg.subsec_nanos()) / 1_000_000_000f64
            + (verifying_avg.as_secs() as f64);

        report.outputs.verify_avg_ms = Some((verifying_avg * 1000.0) as u64);

        (Some(pub_inputs), Some(priv_inputs), Some(data))
    };

    if *circuit || *groth || *bench {
        total_proving += do_circuit_work(&pp, pub_in, priv_in, &params, &mut report)?;
    }

    if let Some(data) = d {
        if *extract {
            let start = Instant::now();
            let decoded_data = ZigZagDrgPoRep::<H>::extract_all(&pp, &replica_id, &data)?;
            let extracting = start.elapsed();
            report.outputs.extracting = Some(extracting.as_millis() as u64);
            assert_ne!(&(*data), decoded_data.as_slice());
        }
    }

    report.outputs.total_proving_ms = total_proving.as_millis() as u64;

    Ok(report)
}

fn do_circuit_work<H: 'static + Hasher>(
    pp: &<ZigZagDrgPoRep<H> as ProofScheme>::PublicParams,
    pub_in: Option<<ZigZagDrgPoRep<H> as ProofScheme>::PublicInputs>,
    priv_in: Option<<ZigZagDrgPoRep<H> as ProofScheme>::PrivateInputs>,
    params: &Params,
    report: &mut Report,
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
        let mut cs = MetricCS::<Bls12>::new();
        ZigZagCompound::blank_circuit(&pp, &engine_params).synthesize(&mut cs)?;

        report.outputs.circuit_num_inputs = Some(cs.num_inputs() as u64);
        report.outputs.circuit_num_constraints = Some(cs.num_constraints() as u64);
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

            report.outputs.avg_groth_verifying_ms = Some(avg_groth_verifying.as_millis() as u64);

            result
        };
        assert!(verified);
    }

    Ok(proving_time)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Inputs {
    data_size: usize,
    m: usize,
    expansion_degree: usize,
    sloth_iter: usize,
    partitions: usize,
    hasher: String,
    samples: usize,
    layers: usize,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct Outputs {
    avg_groth_verifying_ms: Option<u64>,
    circuit_num_constraints: Option<u64>,
    circuit_num_inputs: Option<u64>,
    extracting: Option<u64>,
    replication_time_ms: Option<u64>,
    replication_time_ns_per_byte: Option<u64>,
    total_proving_ms: u64,
    vanilla_proving_time_us: Option<u64>,
    vanilla_verification_time_us: Option<u64>,
    verify_avg_ms: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    inputs: Inputs,
    outputs: Outputs,
}

impl Report {
    /// Print all results to stdout
    pub fn print(&self) {
        serde_json::to_writer(io::stdout(), &self).expect("cannot write report-JSON to stdout");
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

    let report = match params.hasher.as_ref() {
        "pedersen" => generate_report::<PedersenHasher>(params)?,
        "sha256" => generate_report::<Sha256Hasher>(params)?,
        "blake2s" => generate_report::<Blake2sHasher>(params)?,
        _ => bail!("invalid hasher: {}", params.hasher),
    };

    report.print();

    Ok(())
}
