use serde::{Deserialize, Serialize};

use fil_proofs_tooling::measure;
use filecoin_proofs::constants::{POST_CHALLENGED_NODES, POST_CHALLENGE_COUNT};
use filecoin_proofs::generate_candidates;
use filecoin_proofs::types::{PoStConfig, SectorSize};
#[cfg(feature = "measurements")]
use storage_proofs::measurements::Operation;
#[cfg(feature = "measurements")]
use storage_proofs::measurements::OP_MEASUREMENTS;
use storage_proofs::sector::SectorId;

use crate::shared::{
    create_replicas, prove_replicas, CommitReplicaOutput, PreCommitReplicaOutput, CHALLENGE_COUNT,
    PROVER_ID, RANDOMNESS,
};

#[derive(Default, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FlarpInputs {
    //    window_size_mib: usize,
    sector_size_bytes: usize,
    //    drg_parents: usize,
    //    expander_parents: usize,
    //    graph_parents: usize,
    //    porep_challenges: usize,
    //    post_challenges: usize,
    //    proofs_block_fraction: usize,
    //    regeneration_fraction: usize,
    //    stacked_layers: usize,
    //    wrapper_lookup_with_mtree: usize,
    //    wrapper_parents_all: usize,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FlarpOutputs {
    encoding_cpu_time_ms: u64,
    encoding_wall_time_ms: u64,
    generate_tree_c_cpu_time_ms: u64,
    generate_tree_c_wall_time_ms: u64,
    porep_proof_gen_cpu_time_ms: u64,
    porep_proof_gen_wall_time_ms: u64,
    tree_r_last_cpu_time_ms: u64,
    tree_r_last_wall_time_ms: u64,
    comm_d_cpu_time_ms: u64,
    comm_d_wall_time_ms: u64,
    encode_window_time_all_cpu_time_ms: u64,
    encode_window_time_all_wall_time_ms: u64,
    window_comm_leaves_time_cpu_time_ms: u64,
    window_comm_leaves_time_wall_time_ms: u64,
    porep_commit_time_cpu_time_ms: u64,
    porep_commit_time_wall_time_ms: u64,
    post_inclusion_proofs_cpu_time_ms: u64,
    post_inclusion_proofs_time_ms: u64,
    post_finalize_ticket_cpu_time_ms: u64,
    post_finalize_ticket_time_ms: u64,
    post_read_challenged_range_cpu_time_ms: u64,
    post_read_challenged_range_time_ms: u64,
    post_partial_ticket_hash_cpu_time_ms: u64,
    post_partial_ticket_hash_time_ms: u64,
}

#[cfg(not(feature = "measurements"))]
fn augment_with_op_measurements(mut _output: &mut FlarpOutputs) {}

#[cfg(feature = "measurements")]
fn augment_with_op_measurements(mut output: &mut FlarpOutputs) {
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
        use Operation::*;
        let cpu_time = m.cpu_time.as_millis() as u64;
        let wall_time = m.wall_time.as_millis() as u64;

        match m.op {
            GenerateTreeC => {
                output.generate_tree_c_cpu_time_ms = cpu_time;
                output.generate_tree_c_wall_time_ms = wall_time;
            }
            GenerateTreeRLast => {
                output.tree_r_last_cpu_time_ms = cpu_time;
                output.tree_r_last_wall_time_ms = wall_time;
            }
            CommD => {
                output.comm_d_cpu_time_ms = cpu_time;
                output.comm_d_wall_time_ms = wall_time;
            }
            EncodeWindowTimeAll => {
                output.encode_window_time_all_cpu_time_ms = cpu_time;
                output.encode_window_time_all_wall_time_ms = wall_time;
            }
            WindowCommLeavesTime => {
                output.window_comm_leaves_time_cpu_time_ms = cpu_time;
                output.window_comm_leaves_time_wall_time_ms = wall_time;
            }
            PorepCommitTime => {
                output.porep_commit_time_cpu_time_ms = cpu_time;
                output.porep_commit_time_wall_time_ms = wall_time;
            }
            PostInclusionProofs => {
                output.post_inclusion_proofs_cpu_time_ms = cpu_time;
                output.post_inclusion_proofs_time_ms = wall_time;
            }
            PostFinalizeTicket => {
                output.post_finalize_ticket_cpu_time_ms = cpu_time;
                output.post_finalize_ticket_time_ms = wall_time;
            }
            PostReadChallengedRange => {
                output.post_read_challenged_range_cpu_time_ms = cpu_time;
                output.post_read_challenged_range_time_ms = wall_time;
            }
            PostPartialTicketHash => {
                output.post_partial_ticket_hash_cpu_time_ms = cpu_time;
                output.post_partial_ticket_hash_time_ms = wall_time;
            }
        }
    }
}

pub fn run(inputs: FlarpInputs, skip_seal_proof: bool, skip_post_proof: bool) -> FlarpOutputs {
    let mut outputs = FlarpOutputs::default();

    let sector_size = SectorSize(inputs.sector_size_bytes as u64);

    let (cfg, mut created) = create_replicas(sector_size, 1);

    let sector_id: SectorId = *created
        .keys()
        .nth(0)
        .expect("create_replicas produced no replicas");

    if !skip_seal_proof {
        let mut proved = prove_replicas(cfg, &created);

        let seal_commit: CommitReplicaOutput = proved
            .remove(&sector_id)
            .expect("failed to get seal commit from map");

        outputs.porep_proof_gen_cpu_time_ms = seal_commit.measurement.cpu_time.as_millis() as u64;
        outputs.porep_proof_gen_wall_time_ms = seal_commit.measurement.wall_time.as_millis() as u64;
    }

    let replica_info: PreCommitReplicaOutput = created
        .remove(&sector_id)
        .expect("failed to get replica from map");

    // replica_info is moved into the PoSt scope
    let encoding_wall_time_ms = replica_info.measurement.wall_time.as_millis() as u64;
    let encoding_cpu_time_ms = replica_info.measurement.cpu_time.as_millis() as u64;

    if !skip_post_proof {
        // Measure PoSt generation and verification.
        let post_config = PoStConfig {
            sector_size,
            challenge_count: POST_CHALLENGE_COUNT,
            challenged_nodes: POST_CHALLENGED_NODES,
        };

        let _gen_candidates_measurement = measure(|| {
            generate_candidates(
                post_config,
                &RANDOMNESS,
                CHALLENGE_COUNT,
                &vec![(sector_id, replica_info.private_replica_info)]
                    .into_iter()
                    .collect(),
                PROVER_ID,
            )
        })
        .expect("failed to generate post candidates");

        //    let candidates = &gen_candidates_measurement.return_value;
        //
        //    let gen_post_measurement = measure(|| {
        //        generate_post(
        //            post_config,
        //            &CHALLENGE_SEED,
        //            &priv_replica_info,
        //            candidates
        //                .iter()
        //                .cloned()
        //                .map(Into::into)
        //                .collect::<Vec<_>>(),
        //            PROVER_ID,
        //        )
        //    })
        //    .expect("failed to generate PoSt");
        //
        //    let verify_post_measurement = measure(|| {
        //        verify_post(
        //            post_config,
        //            &CHALLENGE_SEED,
        //            CHALLENGE_COUNT,
        //            &gen_post_measurement.return_value,
        //            &pub_replica_info,
        //            &candidates
        //                .iter()
        //                .cloned()
        //                .map(Into::into)
        //                .collect::<Vec<_>>(),
        //            PROVER_ID,
        //        )
        //    })
        //    .expect("verify_post function returned an error");
        //
        //    assert!(
        //        verify_post_measurement.return_value,
        //        "generated PoSt was invalid"
        //    );
    }

    outputs.encoding_wall_time_ms = encoding_wall_time_ms;
    outputs.encoding_cpu_time_ms = encoding_cpu_time_ms;

    augment_with_op_measurements(&mut outputs);

    outputs
}
