use std::collections::BTreeMap;
use std::io::{stdout, Seek, SeekFrom, Write};

use fil_proofs_tooling::shared::{PROVER_ID, RANDOMNESS, TICKET_BYTES};
use fil_proofs_tooling::{measure, Metadata};
use filecoin_proofs::constants::{
    POREP_PARTITIONS, WINDOW_POST_CHALLENGE_COUNT, WINDOW_POST_SECTOR_COUNT,
};
use filecoin_proofs::types::{
    PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, SectorSize,
    UnpaddedBytesAmount,
};
use filecoin_proofs::{
    add_piece, generate_piece_commitment, generate_window_post, seal_commit_phase1,
    seal_commit_phase2, seal_pre_commit_phase1, seal_pre_commit_phase2, validate_cache_for_commit,
    validate_cache_for_precommit_phase2, verify_window_post, with_shape, PoStType,
    PrivateReplicaInfo, PublicReplicaInfo,
};
use log::info;
use serde::Serialize;
use storage_proofs::merkle::MerkleTreeTrait;
use storage_proofs::sector::SectorId;
use tempfile::NamedTempFile;

const SECTOR_ID: u64 = 0;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Inputs {
    sector_size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Outputs {
    seal_pre_commit_phase1_cpu_time_ms: u64,
    seal_pre_commit_phase1_wall_time_ms: u64,
    validate_cache_for_precommit_phase2_cpu_time_ms: u64,
    validate_cache_for_precommit_phase2_wall_time_ms: u64,
    seal_pre_commit_phase2_cpu_time_ms: u64,
    seal_pre_commit_phase2_wall_time_ms: u64,
    validate_cache_for_commit_cpu_time_ms: u64,
    validate_cache_for_commit_wall_time_ms: u64,
    seal_commit_phase1_cpu_time_ms: u64,
    seal_commit_phase1_wall_time_ms: u64,
    seal_commit_phase2_cpu_time_ms: u64,
    seal_commit_phase2_wall_time_ms: u64,
    gen_window_post_cpu_time_ms: u64,
    gen_window_post_wall_time_ms: u64,
    verify_window_post_cpu_time_ms: u64,
    verify_window_post_wall_time_ms: u64,
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

pub fn run_window_post_bench<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
) -> anyhow::Result<()> {
    let sector_size_unpadded_bytes_ammount =
        UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));

    // Create files for the staged and sealed sectors.
    let mut staged_file =
        NamedTempFile::new().expect("could not create temp file for staged sector");

    let sealed_file = NamedTempFile::new().expect("could not create temp file for sealed sector");

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

    let arbitrary_porep_id = [99; 32];

    // Replicate the staged sector, write the replica file to `sealed_path`.
    let porep_config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS
                .read()
                .unwrap()
                .get(&(sector_size))
                .unwrap(),
        ),
        porep_id: arbitrary_porep_id,
    };
    let cache_dir = tempfile::tempdir().unwrap();
    let sector_id = SectorId::from(SECTOR_ID);

    let seal_pre_commit_phase1_measurement = measure(|| {
        seal_pre_commit_phase1::<_, _, _, Tree>(
            porep_config,
            cache_dir.path(),
            staged_file.path(),
            sealed_file.path(),
            PROVER_ID,
            sector_id,
            TICKET_BYTES,
            &piece_infos,
        )
    })
    .expect("failed in seal_pre_commit_phase1");
    let phase1_output = seal_pre_commit_phase1_measurement.return_value;

    let validate_cache_for_precommit_phase2_measurement = measure(|| {
        validate_cache_for_precommit_phase2::<_, _, Tree>(
            cache_dir.path(),
            sealed_file.path(),
            &phase1_output,
        )
    })
    .expect("failed to validate cache for precommit phase2");

    let seal_pre_commit_phase2_measurement = measure(|| {
        seal_pre_commit_phase2::<_, _, Tree>(
            porep_config,
            phase1_output,
            cache_dir.path(),
            sealed_file.path(),
        )
    })
    .expect("failed in seal_pre_commit_phase2");
    let seal_pre_commit_output = seal_pre_commit_phase2_measurement.return_value;

    let seed = [0u8; 32];
    let comm_r = seal_pre_commit_output.comm_r;

    let validate_cache_for_commit_measurement =
        measure(|| validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_file.path()))
            .expect("failed to validate cache for commit");

    let seal_commit_phase1_measurement = measure(|| {
        seal_commit_phase1::<_, Tree>(
            porep_config,
            cache_dir.path(),
            sealed_file.path(),
            PROVER_ID,
            sector_id,
            TICKET_BYTES,
            seed,
            seal_pre_commit_output,
            &piece_infos,
        )
    })
    .expect("failed in seal_commit_phase1");
    let phase1_output = seal_commit_phase1_measurement.return_value;

    let seal_commit_phase2_measurement =
        measure(|| seal_commit_phase2::<Tree>(porep_config, phase1_output, PROVER_ID, sector_id))
            .expect("failed in seal_commit_phase2");

    let pub_replica = PublicReplicaInfo::new(comm_r).expect("failed to create public replica info");

    let priv_replica = PrivateReplicaInfo::<Tree>::new(
        sealed_file.path().to_path_buf(),
        comm_r,
        cache_dir.into_path(),
    )
    .expect("failed to create private replica info");

    // Store the replica's private and publicly facing info for proving and verifying respectively.
    let mut pub_replica_info: BTreeMap<SectorId, PublicReplicaInfo> = BTreeMap::new();
    let mut priv_replica_info: BTreeMap<SectorId, PrivateReplicaInfo<Tree>> = BTreeMap::new();

    pub_replica_info.insert(sector_id, pub_replica);
    priv_replica_info.insert(sector_id, priv_replica);

    // Measure PoSt generation and verification.
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        sector_count: *WINDOW_POST_SECTOR_COUNT
            .read()
            .unwrap()
            .get(&sector_size)
            .unwrap(),
        typ: PoStType::Window,
        priority: true,
    };

    let gen_window_post_measurement = measure(|| {
        generate_window_post::<Tree>(&post_config, &RANDOMNESS, &priv_replica_info, PROVER_ID)
    })
    .expect("failed to generate window post");

    let proof = &gen_window_post_measurement.return_value;

    let verify_window_post_measurement = measure(|| {
        verify_window_post::<Tree>(
            &post_config,
            &RANDOMNESS,
            &pub_replica_info,
            PROVER_ID,
            &proof,
        )
    })
    .expect("failed to verify window post proof");

    let report = Report {
        inputs: Inputs { sector_size },
        outputs: Outputs {
            seal_pre_commit_phase1_cpu_time_ms: seal_pre_commit_phase1_measurement
                .cpu_time
                .as_millis() as u64,
            seal_pre_commit_phase1_wall_time_ms: seal_pre_commit_phase1_measurement
                .wall_time
                .as_millis() as u64,
            validate_cache_for_precommit_phase2_cpu_time_ms:
                validate_cache_for_precommit_phase2_measurement
                    .cpu_time
                    .as_millis() as u64,
            validate_cache_for_precommit_phase2_wall_time_ms:
                validate_cache_for_precommit_phase2_measurement
                    .wall_time
                    .as_millis() as u64,
            seal_pre_commit_phase2_cpu_time_ms: seal_pre_commit_phase2_measurement
                .cpu_time
                .as_millis() as u64,
            seal_pre_commit_phase2_wall_time_ms: seal_pre_commit_phase2_measurement
                .wall_time
                .as_millis() as u64,
            validate_cache_for_commit_cpu_time_ms: validate_cache_for_commit_measurement
                .cpu_time
                .as_millis() as u64,
            validate_cache_for_commit_wall_time_ms: validate_cache_for_commit_measurement
                .wall_time
                .as_millis() as u64,
            seal_commit_phase1_cpu_time_ms: seal_commit_phase1_measurement.cpu_time.as_millis()
                as u64,
            seal_commit_phase1_wall_time_ms: seal_commit_phase1_measurement.wall_time.as_millis()
                as u64,
            seal_commit_phase2_cpu_time_ms: seal_commit_phase2_measurement.cpu_time.as_millis()
                as u64,
            seal_commit_phase2_wall_time_ms: seal_commit_phase2_measurement.wall_time.as_millis()
                as u64,
            gen_window_post_cpu_time_ms: gen_window_post_measurement.cpu_time.as_millis() as u64,
            gen_window_post_wall_time_ms: gen_window_post_measurement.wall_time.as_millis() as u64,
            verify_window_post_cpu_time_ms: verify_window_post_measurement.cpu_time.as_millis()
                as u64,
            verify_window_post_wall_time_ms: verify_window_post_measurement.wall_time.as_millis()
                as u64,
        },
    };

    // Create a JSON serializable report that we print to stdout (that will later be parsed using
    // the CLI JSON parser `jq`).
    report.print();
    Ok(())
}

pub fn run(sector_size: usize) -> anyhow::Result<()> {
    info!("Benchy Window PoSt: sector-size={}", sector_size,);

    with_shape!(
        sector_size as u64,
        run_window_post_bench,
        sector_size as u64
    )
}
