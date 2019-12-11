use std::io::{stdout, Seek, SeekFrom, Write};

use fil_proofs_tooling::{measure, FuncMeasurement, Metadata};
use filecoin_proofs::constants::{
    DEFAULT_POREP_PROOF_PARTITIONS, POST_CHALLENGED_NODES, POST_CHALLENGE_COUNT,
};
use filecoin_proofs::types::{
    PaddedBytesAmount, PoRepConfig, PoStConfig, SectorSize, UnpaddedBytesAmount,
};
use filecoin_proofs::{
    add_piece, generate_candidates, generate_piece_commitment, seal_commit, seal_pre_commit,
    PieceInfo, PrivateReplicaInfo, PublicReplicaInfo, SealCommitOutput, SealPreCommitOutput,
};
use serde::Serialize;
use storage_proofs::sector::SectorId;
use tempfile::NamedTempFile;

#[cfg(feature = "measurements")]
use storage_proofs::measurements::Operation;
#[cfg(feature = "measurements")]
use storage_proofs::measurements::OP_MEASUREMENTS;

const CHALLENGE_COUNT: u64 = 1;
const PROVER_ID: [u8; 32] = [0; 32];
const RANDOMNESS: [u8; 32] = [0; 32];
const TICKET_BYTES: [u8; 32] = [1; 32];

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Inputs {
    sector_size_bytes: u64,
}

#[derive(Default, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
struct Outputs {
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

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Report {
    inputs: Inputs,
    outputs: Outputs,
}

#[cfg(not(feature = "measurements"))]
fn augment_with_op_measurements(mut _report: &mut Report) {}

#[cfg(feature = "measurements")]
fn augment_with_op_measurements(mut report: &mut Report) {
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
                report.outputs.generate_tree_c_cpu_time_ms = cpu_time;
                report.outputs.generate_tree_c_wall_time_ms = wall_time;
            }
            GenerateTreeRLast => {
                report.outputs.tree_r_last_cpu_time_ms = cpu_time;
                report.outputs.tree_r_last_wall_time_ms = wall_time;
            }
            CommD => {
                report.outputs.comm_d_cpu_time_ms = cpu_time;
                report.outputs.comm_d_wall_time_ms = wall_time;
            }
            EncodeWindowTimeAll => {
                report.outputs.encode_window_time_all_cpu_time_ms = cpu_time;
                report.outputs.encode_window_time_all_wall_time_ms = wall_time;
            }
            WindowCommLeavesTime => {
                report.outputs.window_comm_leaves_time_cpu_time_ms = cpu_time;
                report.outputs.window_comm_leaves_time_wall_time_ms = wall_time;
            }
            PorepCommitTime => {
                report.outputs.porep_commit_time_cpu_time_ms = cpu_time;
                report.outputs.porep_commit_time_wall_time_ms = wall_time;
            }
            PostInclusionProofs => {
                report.outputs.post_inclusion_proofs_cpu_time_ms = cpu_time;
                report.outputs.post_inclusion_proofs_time_ms = wall_time;
            }
            PostFinalizeTicket => {
                report.outputs.post_finalize_ticket_cpu_time_ms = cpu_time;
                report.outputs.post_finalize_ticket_time_ms = wall_time;
            }
            PostReadChallengedRange => {
                report.outputs.post_read_challenged_range_cpu_time_ms = cpu_time;
                report.outputs.post_read_challenged_range_time_ms = wall_time;
            }
            PostPartialTicketHash => {
                report.outputs.post_partial_ticket_hash_cpu_time_ms = cpu_time;
                report.outputs.post_partial_ticket_hash_time_ms = wall_time;
            }
        }
    }
}

struct PreCommitReplicaOutput {
    piece_info: Vec<PieceInfo>,
    private_replica_info: PrivateReplicaInfo,
    public_replica_info: PublicReplicaInfo,
    measurement: FuncMeasurement<SealPreCommitOutput>,
}

struct CommitReplicaOutput {
    measurement: FuncMeasurement<SealCommitOutput>,
}

fn create_piece(piece_bytes: UnpaddedBytesAmount) -> (NamedTempFile, PieceInfo) {
    let buf: Vec<u8> = (0..usize::from(piece_bytes))
        .map(|_| rand::random::<u8>())
        .collect();

    let mut file = NamedTempFile::new().expect("failed to create piece file");

    file.write_all(&buf)
        .expect("failed to write buffer to piece file");

    file.as_file_mut()
        .sync_all()
        .expect("failed to sync piece file");

    file.as_file_mut()
        .seek(SeekFrom::Start(0))
        .expect("failed to seek to beginning of piece file");

    let info = generate_piece_commitment(file.as_file_mut(), piece_bytes)
        .expect("failed to generate piece commitment");

    file.as_file_mut()
        .seek(SeekFrom::Start(0))
        .expect("failed to seek to beginning of piece file");

    (file, info)
}

fn create_replicas(
    sector_size_bytes: usize,
    qty_sectors: usize,
) -> (
    PoRepConfig,
    std::collections::BTreeMap<SectorId, PreCommitReplicaOutput>,
) {
    let sector_size_unpadded_bytes_ammount =
        UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size_bytes as u64));

    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size_bytes as u64),
        partitions: DEFAULT_POREP_PROOF_PARTITIONS,
    };

    let mut out: std::collections::BTreeMap<SectorId, PreCommitReplicaOutput> = Default::default();

    for _ in 0..qty_sectors {
        let sector_id = SectorId::from(rand::random::<u64>());

        let cache_dir = tempfile::tempdir().expect("failed to create cache dir");

        let mut staged_file =
            NamedTempFile::new().expect("could not create temp file for staged sector");

        let sealed_file =
            NamedTempFile::new().expect("could not create temp file for sealed sector");

        let sealed_path_string = sealed_file
            .path()
            .to_str()
            .expect("file name is not a UTF-8 string");

        let (mut piece_file, piece_info) = create_piece(UnpaddedBytesAmount::from(
            PaddedBytesAmount(sector_size_bytes as u64),
        ));

        add_piece(
            &mut piece_file,
            &mut staged_file,
            sector_size_unpadded_bytes_ammount,
            &[],
        )
        .expect("failed to add piece to staged sector");

        let seal_pre_commit_output = measure(|| {
            seal_pre_commit(
                porep_config,
                cache_dir.path(),
                staged_file.path(),
                sealed_file.path(),
                PROVER_ID,
                sector_id,
                TICKET_BYTES,
                &vec![piece_info.clone()],
            )
        })
        .expect("seal_pre_commit produced an error");

        let priv_info = PrivateReplicaInfo::new(
            sealed_path_string.to_string(),
            seal_pre_commit_output.return_value.comm_r,
            cache_dir.into_path(),
        )
        .expect("failed to create PrivateReplicaInfo");

        let pub_info = PublicReplicaInfo::new(seal_pre_commit_output.return_value.comm_r)
            .expect("failed to create PublicReplicaInfo");

        out.insert(
            sector_id,
            PreCommitReplicaOutput {
                piece_info: vec![piece_info],
                measurement: seal_pre_commit_output,
                private_replica_info: priv_info,
                public_replica_info: pub_info,
            },
        );
    }

    (porep_config, out)
}

fn prove_replicas(
    cfg: PoRepConfig,
    input: &std::collections::BTreeMap<SectorId, PreCommitReplicaOutput>,
) -> std::collections::BTreeMap<SectorId, CommitReplicaOutput> {
    let mut out: std::collections::BTreeMap<SectorId, CommitReplicaOutput> = Default::default();

    for (k, v) in input.iter() {
        let m = measure(|| {
            seal_commit(
                cfg,
                v.private_replica_info.cache_dir_path(),
                PROVER_ID,
                *k,
                TICKET_BYTES,
                RANDOMNESS,
                v.measurement.return_value.clone(),
                &v.piece_info,
            )
        })
        .expect("failed to prove sector");

        out.insert(*k, CommitReplicaOutput { measurement: m });
    }

    out
}

pub fn run(sector_size_bytes: usize) -> anyhow::Result<()> {
    let (cfg, mut created) = create_replicas(sector_size_bytes, 1);

    let mut proved = prove_replicas(cfg, &created);

    let sector_id: SectorId = created
        .keys()
        .nth(0)
        .expect("create_replicas produced no replicas")
        .clone();

    let replica_info: PreCommitReplicaOutput = created
        .remove(&sector_id)
        .expect("failed to get replica from map");

    let seal_commit: CommitReplicaOutput = proved
        .remove(&sector_id)
        .expect("failed to get seal commit from map");

    let encoding_wall_time_ms = replica_info.measurement.wall_time.as_millis() as u64;
    let encoding_cpu_time_ms = replica_info.measurement.cpu_time.as_millis() as u64;

    // Measure PoSt generation and verification.
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size_bytes as u64),
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

    let mut outputs = Outputs::default();
    outputs.porep_proof_gen_cpu_time_ms = seal_commit.measurement.cpu_time.as_millis() as u64;
    outputs.porep_proof_gen_wall_time_ms = seal_commit.measurement.wall_time.as_millis() as u64;
    outputs.encoding_wall_time_ms = encoding_wall_time_ms;
    outputs.encoding_cpu_time_ms = encoding_cpu_time_ms;

    let mut report: Report = Report {
        inputs: Inputs {
            sector_size_bytes: sector_size_bytes as u64,
        },
        outputs,
    };

    augment_with_op_measurements(&mut report);

    let wrapped = Metadata::wrap(&report).expect("failed to retrieve metadata");
    serde_json::to_writer(stdout(), &wrapped).expect("cannot write report JSON to stdout");

    Ok(())
}
