use std::io::{stdout, Seek, SeekFrom, Write};

use fil_proofs_tooling::{measure, Metadata};
use filecoin_proofs::constants::{
    POREP_PARTITIONS, WINNING_POST_CHALLENGE_COUNT, WINNING_POST_SECTOR_COUNT,
};
use filecoin_proofs::types::{
    PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, SectorSize,
    UnpaddedBytesAmount,
};
use filecoin_proofs::{
    add_piece, generate_piece_commitment, generate_winning_post,
    generate_winning_post_sector_challenge, seal_commit_phase1, seal_commit_phase2,
    seal_pre_commit_phase1, seal_pre_commit_phase2, validate_cache_for_commit,
    validate_cache_for_precommit_phase2, verify_winning_post, with_shape, PoStType,
    PrivateReplicaInfo, PublicReplicaInfo,
};
use log::info;
use serde::Serialize;
use storage_proofs::merkle::MerkleTreeTrait;
use storage_proofs::sector::SectorId;
use tempfile::NamedTempFile;

use crate::shared::{PROVER_ID, RANDOMNESS, TICKET_BYTES};

const SECTOR_ID: u64 = 0;

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Inputs {
    sector_size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Outputs {
    gen_winning_post_cpu_time_ms: u64,
    gen_winning_post_wall_time_ms: u64,
    verify_winning_post_cpu_time_ms: u64,
    verify_winning_post_wall_time_ms: u64,
    gen_winning_post_sector_challenge_cpu_time_ms: u64,
    gen_winning_post_sector_challenge_wall_time_ms: u64,
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

pub fn run_fallback_post_bench<Tree: 'static + MerkleTreeTrait>(
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
    };
    let cache_dir = tempfile::tempdir().unwrap();
    let sector_id = SectorId::from(SECTOR_ID);
    let sector_count = WINNING_POST_SECTOR_COUNT;

    let phase1_output = seal_pre_commit_phase1::<_, _, _, Tree>(
        porep_config,
        cache_dir.path(),
        staged_file.path(),
        sealed_file.path(),
        PROVER_ID,
        sector_id,
        TICKET_BYTES,
        &piece_infos,
    )?;

    validate_cache_for_precommit_phase2::<_, _, Tree>(
        cache_dir.path(),
        sealed_file.path(),
        &phase1_output,
    )?;

    let seal_pre_commit_output = seal_pre_commit_phase2::<_, _, Tree>(
        porep_config,
        phase1_output,
        cache_dir.path(),
        sealed_file.path(),
    )?;

    let seed = [0u8; 32];
    let comm_r = seal_pre_commit_output.comm_r;

    validate_cache_for_commit::<_, _, Tree>(cache_dir.path(), sealed_file.path())?;

    let phase1_output = seal_commit_phase1::<_, Tree>(
        porep_config,
        cache_dir.path(),
        sealed_file.path(),
        PROVER_ID,
        sector_id,
        TICKET_BYTES,
        seed,
        seal_pre_commit_output,
        &piece_infos,
    )?;

    let _seal_commit_output =
        seal_commit_phase2::<Tree>(porep_config, phase1_output, PROVER_ID, sector_id)?;

    let pub_replica = PublicReplicaInfo::new(comm_r).expect("failed to create public replica info");

    let priv_replica = PrivateReplicaInfo::<Tree>::new(
        sealed_file.path().to_path_buf(),
        comm_r,
        cache_dir.into_path(),
    )
    .expect("failed to create private replica info");

    // Store the replica's private and publicly facing info for proving and verifying respectively.
    let pub_replica_info = vec![(sector_id, pub_replica)];
    let priv_replica_info = vec![(sector_id, priv_replica)];

    let post_config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: true,
    };

    let gen_winning_post_sector_challenge_measurement = measure(|| {
        generate_winning_post_sector_challenge::<Tree>(
            &post_config,
            &RANDOMNESS,
            sector_count as u64,
            PROVER_ID,
        )
    })
    .expect("failed to generate winning post sector challenge");

    let gen_winning_post_measurement = measure(|| {
        generate_winning_post::<Tree>(&post_config, &RANDOMNESS, &priv_replica_info[..], PROVER_ID)
    })
    .expect("failed to generate winning post");

    let proof = &gen_winning_post_measurement.return_value;

    let verify_winning_post_measurement = measure(|| {
        verify_winning_post::<Tree>(
            &post_config,
            &RANDOMNESS,
            &pub_replica_info[..],
            PROVER_ID,
            &proof,
        )
    })
    .expect("failed to verify winning post proof");

    // Create a JSON serializable report that we print to stdout (that will later be parsed using
    // the CLI JSON parser `jq`).
    let report = Report {
        inputs: Inputs { sector_size },
        outputs: Outputs {
            gen_winning_post_cpu_time_ms: gen_winning_post_measurement.cpu_time.as_millis() as u64,
            gen_winning_post_wall_time_ms: gen_winning_post_measurement.wall_time.as_millis()
                as u64,
            verify_winning_post_cpu_time_ms: verify_winning_post_measurement.cpu_time.as_millis()
                as u64,
            verify_winning_post_wall_time_ms: verify_winning_post_measurement.wall_time.as_millis()
                as u64,
            gen_winning_post_sector_challenge_cpu_time_ms:
                gen_winning_post_sector_challenge_measurement
                    .cpu_time
                    .as_millis() as u64,
            gen_winning_post_sector_challenge_wall_time_ms:
                gen_winning_post_sector_challenge_measurement
                    .wall_time
                    .as_millis() as u64,
        },
    };
    report.print();
    Ok(())
}

pub fn run(sector_size: usize) -> anyhow::Result<()> {
    println!("Benchy Fallback PoSt: sector-size={}", sector_size,);
    info!("Benchy Fallback PoSt: sector-size={}", sector_size,);

    with_shape!(
        sector_size as u64,
        run_fallback_post_bench,
        sector_size as u64
    )
}
