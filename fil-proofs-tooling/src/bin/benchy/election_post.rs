use std::collections::BTreeMap;
use std::io::{stdout, Seek, SeekFrom, Write};
use std::sync::atomic::Ordering;

use fil_proofs_tooling::{measure, Metadata};
use filecoin_proofs::constants::{
    DEFAULT_POREP_PROOF_PARTITIONS, POST_CHALLENGED_NODES, POST_CHALLENGE_COUNT,
};
use filecoin_proofs::types::{
    PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, SectorSize,
    UnpaddedBytesAmount,
};
use filecoin_proofs::{
    add_piece, generate_candidates, generate_piece_commitment, generate_post, seal_commit,
    seal_pre_commit, verify_post, PrivateReplicaInfo, PublicReplicaInfo,
};
use log::info;
use serde::Serialize;
use storage_proofs::sector::SectorId;
use tempfile::NamedTempFile;

use crate::shared::{CHALLENGE_COUNT, PROVER_ID, RANDOMNESS, TICKET_BYTES};

const SECTOR_ID: u64 = 0;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Inputs {
    sector_size: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Outputs {
    candidates_cpu_time_ms: u64,
    proving_cpu_time_ms: u64,
    proving_wall_time_ms: u64,
    verifying_wall_time_ms: u64,
    verifying_cpu_time_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Report {
    inputs: Inputs,
    outputs: Outputs,
}

impl Report {
    /// Print all results to stdout
    pub fn print(&self) {
        let wrapped = Metadata::wrap(&self).expect("failed to retrieve metadata");
        serde_json::to_writer(stdout(), &wrapped).expect("cannot write report JSON to stdout");
    }
}

pub fn run(sector_size: usize) -> anyhow::Result<()> {
    info!("Benchy Election PoSt: sector-size={}", sector_size,);

    let sector_size_unpadded_bytes_ammount =
        UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size as u64));

    // Create files for the staged and sealed sectors.
    let mut staged_file =
        NamedTempFile::new().expect("could not create temp file for staged sector");

    let sealed_file = NamedTempFile::new().expect("could not create temp file for sealed sector");

    let sealed_path_string = sealed_file
        .path()
        .to_str()
        .expect("file name is not a UTF-8 string")
        .to_string();

    // Generate the data from which we will create a replica, we will then prove the continued
    // storage of that replica using the PoSt.
    let piece_bytes: Vec<u8> = (0..usize::from(sector_size_unpadded_bytes_ammount))
        .map(|_| rand::random::<u8>())
        .collect();

    let mut piece_file = NamedTempFile::new()?;
    piece_file.write_all(&piece_bytes)?;
    piece_file.as_file_mut().sync_all()?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    let piece_info =
        generate_piece_commitment(piece_file.as_file_mut(), sector_size_unpadded_bytes_ammount)?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    add_piece(
        &mut piece_file,
        &mut staged_file,
        sector_size_unpadded_bytes_ammount,
        &[],
    )?;

    let piece_infos = vec![piece_info];

    // Replicate the staged sector, write the replica file to `sealed_path`.
    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size as u64),
        partitions: PoRepProofPartitions(DEFAULT_POREP_PROOF_PARTITIONS.load(Ordering::Relaxed)),
    };
    let cache_dir = tempfile::tempdir().unwrap();
    let sector_id = SectorId::from(SECTOR_ID);

    let seal_pre_commit_output = seal_pre_commit(
        porep_config,
        &[cache_dir.path().into()],
        &[staged_file.path().into()],
        &[sealed_file.path().into()],
        &[PROVER_ID],
        &[sector_id],
        &[TICKET_BYTES],
        &[piece_infos.clone()],
    )?
    .into_iter()
    .next()
    .unwrap();

    let seed = [0u8; 32];
    let comm_r = seal_pre_commit_output.comm_r;

    let _seal_commit_output = seal_commit(
        porep_config,
        cache_dir.path(),
        PROVER_ID,
        sector_id,
        TICKET_BYTES,
        seed,
        seal_pre_commit_output,
        &piece_infos,
    )?;

    // Store the replica's private and publicly facing info for proving and verifying respectively.
    let mut pub_replica_info: BTreeMap<SectorId, PublicReplicaInfo> = BTreeMap::new();
    let mut priv_replica_info: BTreeMap<SectorId, PrivateReplicaInfo> = BTreeMap::new();

    pub_replica_info.insert(sector_id, PublicReplicaInfo::new(comm_r)?);

    priv_replica_info.insert(
        sector_id,
        PrivateReplicaInfo::new(sealed_path_string, comm_r, cache_dir.into_path())?,
    );

    // Measure PoSt generation and verification.
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size as u64),
        challenge_count: POST_CHALLENGE_COUNT,
        challenged_nodes: POST_CHALLENGED_NODES,
    };

    let gen_candidates_measurement = measure(|| {
        generate_candidates(
            post_config,
            &RANDOMNESS,
            CHALLENGE_COUNT,
            &priv_replica_info,
            PROVER_ID,
        )
    })
    .expect("failed to generate post candidates");

    let candidates = &gen_candidates_measurement.return_value;

    let gen_post_measurement = measure(|| {
        generate_post(
            post_config,
            &RANDOMNESS,
            &priv_replica_info,
            candidates
                .iter()
                .cloned()
                .map(Into::into)
                .collect::<Vec<_>>(),
            PROVER_ID,
        )
    })
    .expect("failed to generate PoSt");

    let proof = &gen_post_measurement.return_value;

    let verify_post_measurement = measure(|| {
        verify_post(
            post_config,
            &RANDOMNESS,
            CHALLENGE_COUNT,
            proof,
            &pub_replica_info,
            &candidates
                .iter()
                .cloned()
                .map(Into::into)
                .collect::<Vec<_>>(),
            PROVER_ID,
        )
    })
    .expect("failed to verify PoSt");

    // Create a JSON serializable report that we print to stdout (that will later be parsed using
    // the CLI JSON parser `jq`).
    let report = Report {
        inputs: Inputs { sector_size },
        outputs: Outputs {
            candidates_cpu_time_ms: gen_candidates_measurement.cpu_time.as_millis() as u64,
            proving_cpu_time_ms: gen_post_measurement.cpu_time.as_millis() as u64,
            proving_wall_time_ms: gen_post_measurement.wall_time.as_millis() as u64,
            verifying_cpu_time_ms: verify_post_measurement.cpu_time.as_millis() as u64,
            verifying_wall_time_ms: verify_post_measurement.wall_time.as_millis() as u64,
        },
    };

    report.print();
    Ok(())
}
