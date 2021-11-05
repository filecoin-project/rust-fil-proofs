use std::fs::remove_file;
use std::str::FromStr;

use bellperson::{bls::Bls12, util_cs::bench_cs::BenchCS, Circuit};
use fil_proofs_tooling::{
    measure,
    shared::{create_replicas, PROVER_ID, RANDOMNESS, TICKET_BYTES},
    Metadata,
};
use filecoin_hashers::sha256::Sha256Hasher;
use filecoin_proofs::{
    clear_cache, parameters::public_params, seal_commit_phase1, seal_commit_phase2,
    validate_cache_for_commit, DefaultOctLCTree, DefaultOctTree, PaddedBytesAmount, PoRepConfig,
    PoRepProofPartitions, SectorSize, DRG_DEGREE, EXP_DEGREE, LAYERS, POREP_MINIMUM_CHALLENGES,
    POREP_PARTITIONS,
};
use log::info;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use serde::{Deserialize, Serialize};
#[cfg(feature = "measurements")]
use storage_proofs_core::measurements::{Operation, OP_MEASUREMENTS};
use storage_proofs_core::{
    api_version::ApiVersion, compound_proof::CompoundProof, parameter_cache::CacheableParameters,
    proof::ProofScheme,
};
use storage_proofs_porep::stacked::{LayerChallenges, SetupParams, StackedCompound, StackedDrg};

const SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];

type ProdbenchTree = DefaultOctTree;

#[derive(Default, Debug, Serialize)]
pub struct ProdbenchReport {
    inputs: ProdbenchInputs,
    outputs: ProdbenchOutputs,
}

#[derive(Default, Debug, Deserialize, Serialize)]
pub struct ProdbenchInputs {
    /// The size of sector.
    sector_size: String,
    porep_challenges: u64,
    porep_partitions: u8,
    post_challenges: u64,
    post_challenged_nodes: u64,
    stacked_layers: u64,
    /// How many sectors should be created in parallel.
    num_sectors: u64,
    api_version: String,
}

impl ProdbenchInputs {
    pub fn sector_size_bytes(&self) -> u64 {
        bytefmt::parse(&self.sector_size).expect("failed to parse sector size")
    }
    pub fn api_version(&self) -> ApiVersion {
        ApiVersion::from_str(&self.api_version).expect("failed to parse api version")
    }
}

#[derive(Default, Debug, Serialize)]
pub struct ProdbenchOutputs {
    comm_d_cpu_time_ms: u64,
    comm_d_wall_time_ms: u64,
    encode_window_time_all_cpu_time_ms: u64,
    encode_window_time_all_wall_time_ms: u64,
    encoding_cpu_time_ms: u64,
    encoding_wall_time_ms: u64,
    generate_tree_c_cpu_time_ms: u64,
    generate_tree_c_wall_time_ms: u64,
    porep_commit_time_cpu_time_ms: u64,
    porep_commit_time_wall_time_ms: u64,
    porep_proof_gen_cpu_time_ms: u64,
    porep_proof_gen_wall_time_ms: u64,
    post_finalize_ticket_cpu_time_ms: u64,
    post_finalize_ticket_time_ms: u64,
    post_partial_ticket_hash_cpu_time_ms: u64,
    post_partial_ticket_hash_time_ms: u64,
    post_proof_gen_cpu_time_ms: u64,
    post_proof_gen_wall_time_ms: u64,
    post_read_challenged_range_cpu_time_ms: u64,
    post_read_challenged_range_time_ms: u64,
    post_verify_cpu_time_ms: u64,
    post_verify_wall_time_ms: u64,
    tree_r_last_cpu_time_ms: u64,
    tree_r_last_wall_time_ms: u64,
    window_comm_leaves_time_cpu_time_ms: u64,
    window_comm_leaves_time_wall_time_ms: u64,
    add_piece_cpu_time_ms: u64,
    add_piece_wall_time_ms: u64,
    generate_piece_commitment_cpu_time_ms: u64,
    generate_piece_commitment_wall_time_ms: u64,
    #[serde(flatten)]
    circuits: CircuitOutputs,
}

#[cfg(not(feature = "measurements"))]
fn augment_with_op_measurements(mut _output: &mut ProdbenchOutputs) {}

#[cfg(feature = "measurements")]
fn augment_with_op_measurements(mut output: &mut ProdbenchOutputs) {
    // drop the tx side of the channel, causing the iterator to yield None
    // see also: https://doc.rust-lang.org/src/std/sync/mpsc/mod.rs.html#368
    OP_MEASUREMENTS
        .0
        .lock()
        .expect("failed to acquire mutex")
        .take();

    let measurements = OP_MEASUREMENTS
        .1
        .lock()
        .expect("failed to acquire lock on rx side of perf channel");

    for m in measurements.iter() {
        let cpu_time = m.cpu_time.as_millis() as u64;
        let wall_time = m.wall_time.as_millis() as u64;

        match m.op {
            Operation::GenerateTreeC => {
                output.generate_tree_c_cpu_time_ms = cpu_time;
                output.generate_tree_c_wall_time_ms = wall_time;
            }
            Operation::GenerateTreeRLast => {
                output.tree_r_last_cpu_time_ms = cpu_time;
                output.tree_r_last_wall_time_ms = wall_time;
            }
            Operation::CommD => {
                output.comm_d_cpu_time_ms = cpu_time;
                output.comm_d_wall_time_ms = wall_time;
            }
            Operation::EncodeWindowTimeAll => {
                output.encode_window_time_all_cpu_time_ms = cpu_time;
                output.encode_window_time_all_wall_time_ms = wall_time;
            }
            Operation::WindowCommLeavesTime => {
                output.window_comm_leaves_time_cpu_time_ms = cpu_time;
                output.window_comm_leaves_time_wall_time_ms = wall_time;
            }
            Operation::PorepCommitTime => {
                output.porep_commit_time_cpu_time_ms = cpu_time;
                output.porep_commit_time_wall_time_ms = wall_time;
            }
            Operation::AddPiece => {
                output.add_piece_cpu_time_ms = cpu_time;
                output.add_piece_wall_time_ms = wall_time;
            }
            Operation::GeneratePieceCommitment => {
                output.generate_piece_commitment_cpu_time_ms = cpu_time;
                output.generate_piece_commitment_wall_time_ms = wall_time;
            }
            _ => {}
        }
    }
}

fn configure_global_config(inputs: &ProdbenchInputs) {
    LAYERS
        .write()
        .expect("LAYERS poisoned")
        .insert(inputs.sector_size_bytes(), inputs.stacked_layers as usize);
    POREP_PARTITIONS
        .write()
        .expect("POREP_PARTITIONS poisoned")
        .insert(inputs.sector_size_bytes(), inputs.porep_partitions);
    POREP_MINIMUM_CHALLENGES
        .write()
        .expect("POREP_MINIMUM_CHALLENGES poisoned")
        .insert(inputs.sector_size_bytes(), inputs.porep_challenges);
}

pub fn run(
    inputs: ProdbenchInputs,
    skip_seal_proof: bool,
    skip_post_proof: bool,
    only_replicate: bool,
    only_add_piece: bool,
) -> Metadata<ProdbenchReport> {
    configure_global_config(&inputs);

    let mut outputs = ProdbenchOutputs::default();

    let sector_size = SectorSize(inputs.sector_size_bytes());
    let arbitrary_porep_id = [123; 32];

    assert!(inputs.num_sectors > 0, "Missing num_sectors");

    let (cfg, repls) = create_replicas::<DefaultOctLCTree>(
        sector_size,
        inputs.num_sectors as usize,
        only_add_piece,
        arbitrary_porep_id,
        inputs.api_version(),
    );

    if only_add_piece || only_replicate {
        augment_with_op_measurements(&mut outputs);
        return Metadata::wrap(ProdbenchReport { inputs, outputs })
            .expect("failed to retrieve metadata");
    }

    let (created, replica_measurement) = repls.expect("unreachable: only_add_piece==false");
    generate_params(&inputs);

    if !skip_seal_proof {
        for (value, (sector_id, replica_info)) in
            replica_measurement.return_value.iter().zip(created.iter())
        {
            let measured = measure(|| {
                validate_cache_for_commit::<_, _, DefaultOctLCTree>(
                    &replica_info.private_replica_info.cache_dir_path(),
                    &replica_info.private_replica_info.replica_path(),
                )?;

                let phase1_output = seal_commit_phase1::<_, DefaultOctLCTree>(
                    cfg,
                    &replica_info.private_replica_info.cache_dir_path(),
                    &replica_info.private_replica_info.replica_path(),
                    PROVER_ID,
                    *sector_id,
                    TICKET_BYTES,
                    RANDOMNESS,
                    value.clone(),
                    &replica_info.piece_info,
                )?;

                clear_cache::<DefaultOctLCTree>(
                    &replica_info.private_replica_info.cache_dir_path(),
                )?;

                seal_commit_phase2(cfg, phase1_output, PROVER_ID, *sector_id)
            })
            .expect("failed to prove sector");

            outputs.porep_proof_gen_cpu_time_ms += measured.cpu_time.as_millis() as u64;
            outputs.porep_proof_gen_wall_time_ms += measured.wall_time.as_millis() as u64;
        }
    }

    if !skip_post_proof {
        // TODO: add winning and window PoSt
    }

    // Clean-up persisted replica files.
    for (_, info) in &created {
        remove_file(info.private_replica_info.replica_path())
            .expect("failed to remove sealed replica file");
    }

    augment_with_op_measurements(&mut outputs);
    outputs.circuits = run_measure_circuits(&inputs);

    Metadata::wrap(ProdbenchReport { inputs, outputs }).expect("failed to retrieve metadata")
}

#[derive(Default, Debug, Serialize)]
struct CircuitOutputs {
    pub porep_constraints: usize,
}

fn run_measure_circuits(i: &ProdbenchInputs) -> CircuitOutputs {
    let porep_constraints = measure_porep_circuit(i);

    CircuitOutputs { porep_constraints }
}

fn measure_porep_circuit(i: &ProdbenchInputs) -> usize {
    let layers = i.stacked_layers as usize;
    let challenge_count = i.porep_challenges as usize;
    let drg_degree = DRG_DEGREE;
    let expansion_degree = EXP_DEGREE;
    let nodes = (i.sector_size_bytes() / 32) as usize;
    let layer_challenges = LayerChallenges::new(layers, challenge_count);

    let arbitrary_porep_id = [222; 32];
    let sp = SetupParams {
        nodes,
        degree: drg_degree,
        expansion_degree,
        porep_id: arbitrary_porep_id,
        layer_challenges,
        api_version: i.api_version(),
    };

    let pp = StackedDrg::<ProdbenchTree, Sha256Hasher>::setup(&sp).expect("failed to setup DRG");

    let mut cs = BenchCS::<Bls12>::new();
    <StackedCompound<_, _> as CompoundProof<StackedDrg<ProdbenchTree, Sha256Hasher>, _>>::blank_circuit(
        &pp,
    )
        .synthesize(&mut cs)
        .expect("failed to synthesize stacked compound");

    cs.num_constraints()
}

fn generate_params(i: &ProdbenchInputs) {
    let sector_size = SectorSize(i.sector_size_bytes());
    let partitions = PoRepProofPartitions(
        *POREP_PARTITIONS
            .read()
            .expect("POREP_PARTITIONS poisoned")
            .get(&i.sector_size_bytes())
            .expect("unknown sector size"),
    );
    info!(
        "generating params: porep: (size: {:?}, partitions: {:?})",
        &sector_size, &partitions
    );
    let dummy_porep_id = [0; 32];

    cache_porep_params(PoRepConfig {
        sector_size,
        partitions,
        porep_id: dummy_porep_id,
        api_version: i.api_version(),
    });
}

fn cache_porep_params(porep_config: PoRepConfig) {
    let public_params = public_params(
        PaddedBytesAmount::from(porep_config),
        usize::from(PoRepProofPartitions::from(porep_config)),
        porep_config.porep_id,
        porep_config.api_version,
    )
    .expect("failed to get public_params");

    {
        let circuit = <StackedCompound<ProdbenchTree, _> as CompoundProof<
            StackedDrg<ProdbenchTree, Sha256Hasher>,
            _,
        >>::blank_circuit(&public_params);
        StackedCompound::<ProdbenchTree, Sha256Hasher>::get_param_metadata(circuit, &public_params)
            .expect("cannot get param metadata");
    }
    {
        let circuit = <StackedCompound<ProdbenchTree, _> as CompoundProof<
            StackedDrg<ProdbenchTree, Sha256Hasher>,
            _,
        >>::blank_circuit(&public_params);
        StackedCompound::<ProdbenchTree, Sha256Hasher>::get_groth_params(
            Some(&mut XorShiftRng::from_seed(SEED)),
            circuit,
            &public_params,
        )
        .expect("failed to get groth params");
    }
    {
        let circuit = <StackedCompound<ProdbenchTree, _> as CompoundProof<
            StackedDrg<ProdbenchTree, Sha256Hasher>,
            _,
        >>::blank_circuit(&public_params);

        StackedCompound::<ProdbenchTree, Sha256Hasher>::get_verifying_key(
            Some(&mut XorShiftRng::from_seed(SEED)),
            circuit,
            &public_params,
        )
        .expect("failed to get verifying key");
    }
}
