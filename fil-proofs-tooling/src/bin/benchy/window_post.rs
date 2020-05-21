use std::collections::BTreeMap;
use std::fs::{create_dir, read, read_to_string, remove_dir_all, File, OpenOptions};
use std::io::{stdout, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context};
use bincode::{deserialize, serialize};
use fil_proofs_tooling::measure::FuncMeasurement;
use fil_proofs_tooling::shared::{PROVER_ID, RANDOMNESS, TICKET_BYTES};
use fil_proofs_tooling::{measure, Metadata};
use filecoin_proofs::constants::{
    POREP_PARTITIONS, WINDOW_POST_CHALLENGE_COUNT, WINDOW_POST_SECTOR_COUNT,
};
use filecoin_proofs::types::{
    PaddedBytesAmount, PieceInfo, PoRepConfig, PoRepProofPartitions, PoStConfig,
    SealCommitPhase1Output, SealPreCommitOutput, SealPreCommitPhase1Output, SectorSize,
    UnpaddedBytesAmount,
};
use filecoin_proofs::{
    add_piece, generate_piece_commitment, generate_window_post, seal_commit_phase1,
    seal_commit_phase2, seal_pre_commit_phase1, seal_pre_commit_phase2, validate_cache_for_commit,
    validate_cache_for_precommit_phase2, verify_window_post, with_shape, PoStType,
    PrivateReplicaInfo, PublicReplicaInfo,
};
use log::info;
use serde::{Deserialize, Serialize};
use storage_proofs::merkle::MerkleTreeTrait;
use storage_proofs::sector::SectorId;

const SECTOR_ID: u64 = 0;

const PIECE_FILE: &str = "piece-file";
const PIECE_INFOS_FILE: &str = "piece-infos-file";
const STAGED_FILE: &str = "staged-file";
const SEALED_FILE: &str = "sealed-file";
const PRECOMMIT_PHASE1_OUTPUT_FILE: &str = "precommit-phase1-output";
const PRECOMMIT_PHASE2_OUTPUT_FILE: &str = "precommit-phase2-output";
const COMMIT_PHASE1_OUTPUT_FILE: &str = "commit-phase1-output";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Inputs {
    sector_size: u64,
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
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

fn get_porep_config(sector_size: u64) -> PoRepConfig {
    let arbitrary_porep_id = [99; 32];

    // Replicate the staged sector, write the replica file to `sealed_path`.
    PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS
                .read()
                .expect("POREP_PARTITONS poisoned")
                .get(&(sector_size))
                .expect("unknown sector size"),
        ),
        porep_id: arbitrary_porep_id,
    }
}

fn run_pre_commit_phases<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    cache_dir: PathBuf,
    skip_precommit_phase1: bool,
    skip_precommit_phase2: bool,
) -> anyhow::Result<((u64, u64), (u64, u64), (u64, u64))> {
    let (seal_pre_commit_phase1_measurement_cpu_time, seal_pre_commit_phase1_measurement_wall_time): (u64, u64) = if skip_precommit_phase1 {
            // generate no-op measurements
        (0, 0)
    } else {
        // Create files for the staged and sealed sectors.
        let staged_file_path = cache_dir.join(STAGED_FILE);
        let mut staged_file = OpenOptions::new().read(true).write(true).create(true).open(&staged_file_path)?;
        info!("*** Created staged file");

        let sealed_file_path = cache_dir.join(SEALED_FILE);
        let _sealed_file = OpenOptions::new().read(true).write(true).create(true).open(&sealed_file_path)?;
        info!("*** Created sealed file");

        let sector_size_unpadded_bytes_amount =
            UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));

        // Generate the data from which we will create a replica, we will then prove the continued
        // storage of that replica using the PoSt.
        let piece_bytes: Vec<u8> = (0..usize::from(sector_size_unpadded_bytes_amount))
            .map(|_| rand::random::<u8>())
            .collect();

        let piece_file_path = cache_dir.join(PIECE_FILE);
        let mut piece_file = OpenOptions::new().read(true).write(true).create(true).open(&piece_file_path)?;
        info!("*** Created piece file");
        piece_file.write_all(&piece_bytes)?;
        piece_file.sync_all()?;
        piece_file.seek(SeekFrom::Start(0))?;

        let piece_info =
            generate_piece_commitment(&mut piece_file, sector_size_unpadded_bytes_amount)?;
        piece_file.seek(SeekFrom::Start(0))?;

        add_piece(
            &mut piece_file,
            &mut staged_file,
            sector_size_unpadded_bytes_amount,
            &[],
        )?;

        let piece_infos = vec![piece_info];
        let sector_id = SectorId::from(SECTOR_ID);
        let porep_config = get_porep_config(sector_size);

        let seal_pre_commit_phase1_measurement: FuncMeasurement<SealPreCommitPhase1Output<Tree>> = measure(|| {
            seal_pre_commit_phase1::<_, _, _, Tree>(
                porep_config,
                cache_dir.clone(),
                staged_file_path.clone(),
                sealed_file_path.clone(),
                PROVER_ID,
                sector_id,
                TICKET_BYTES,
                &piece_infos,
            )
        })
            .expect("failed in seal_pre_commit_phase1");
        let precommit_phase1_output = seal_pre_commit_phase1_measurement.return_value;

        // Persist piece_infos here
        let piece_infos_path = cache_dir.join(PIECE_INFOS_FILE);
        let mut f = File::create(&piece_infos_path)
            .with_context(|| format!("could not create file piece_infos_path={:?}", piece_infos_path))?;
        info!("*** Created piece infos file");
        let piece_infos_json = serde_json::to_string(&piece_infos.to_vec())?;
        f.write_all(piece_infos_json.as_bytes())
            .with_context(|| format!("could not write to file piece_infos_path={:?}", piece_infos_path))?;
        info!("Persisted piece_infos to {:?} of size{}", piece_infos_path, f.metadata()?.len());

        // Persist precommit phase1_output here
        let precommit_phase1_output_path = cache_dir.join(PRECOMMIT_PHASE1_OUTPUT_FILE);
        let mut f = File::create(&precommit_phase1_output_path)
            .with_context(|| format!("could not create file precommit_phase1_output_path={:?}", precommit_phase1_output_path))?;
        info!("*** Created precommit phase1 output file");
        let precommit_phase1_output_bytes = serialize(&precommit_phase1_output)?;
        f.write_all(&precommit_phase1_output_bytes)
            .with_context(|| format!("could not write to file precommit_phase1_output_path={:?}", precommit_phase1_output_path))?;
        info!("Persisted pre-commit phase1 output to {:?}", precommit_phase1_output_path);

        (seal_pre_commit_phase1_measurement.cpu_time.as_millis() as u64, seal_pre_commit_phase1_measurement.wall_time.as_millis() as u64)
    };

    let (
        (
            validate_cache_for_precommit_phase2_measurement_cpu_time,
            validate_cache_for_precommit_phase2_measurement_wall_time,
        ),
        (seal_pre_commit_phase2_measurement_cpu_time, seal_pre_commit_phase2_measurement_wall_time),
    ) = if skip_precommit_phase2 {
        // generate no-op measurements
        ((0, 0), (0, 0))
    } else {
        // Restore precommit phase1_output here
        let precommit_phase1_output = {
            let precommit_phase1_output_path = cache_dir.join(PRECOMMIT_PHASE1_OUTPUT_FILE);
            info!("*** Restoring precommit phase1 output file");
            let precommit_phase1_output_bytes =
                read(&precommit_phase1_output_path).with_context(|| {
                    format!(
                        "could not read file precommit_phase1_output_path={:?}",
                        precommit_phase1_output_path
                    )
                })?;

            let res: SealPreCommitPhase1Output<Tree> = deserialize(&precommit_phase1_output_bytes)?;

            res
        };

        let porep_config = get_porep_config(sector_size);

        let sealed_file_path = cache_dir.join(SEALED_FILE);

        let validate_cache_for_precommit_phase2_measurement: FuncMeasurement<()> = measure(|| {
            validate_cache_for_precommit_phase2::<_, _, Tree>(
                cache_dir.clone(),
                sealed_file_path.clone(),
                &precommit_phase1_output,
            )
        })
        .expect("failed to validate cache for precommit phase2");

        let seal_pre_commit_phase2_measurement: FuncMeasurement<SealPreCommitOutput> =
            measure(|| {
                seal_pre_commit_phase2::<_, _, Tree>(
                    porep_config,
                    precommit_phase1_output,
                    cache_dir.clone(),
                    sealed_file_path.clone(),
                )
            })
            .expect("failed in seal_pre_commit_phase2");
        let precommit_phase2_output = seal_pre_commit_phase2_measurement.return_value;

        // Persist precommit phase2_output here
        let precommit_phase2_output_path = cache_dir.join(PRECOMMIT_PHASE2_OUTPUT_FILE);
        let mut f = File::create(&precommit_phase2_output_path).with_context(|| {
            format!(
                "could not create file precommit_phase2_output_path={:?}",
                precommit_phase2_output_path
            )
        })?;
        info!("*** Created precommit phase2 output file");
        let precommit_phase2_output_bytes = serialize(&precommit_phase2_output)?;
        f.write_all(&precommit_phase2_output_bytes)
            .with_context(|| {
                format!(
                    "could not write to file precommit_phase2_output_path={:?}",
                    precommit_phase2_output_path
                )
            })?;
        info!(
            "Persisted pre-commit phase2 output to {:?}",
            precommit_phase2_output_path
        );

        (
            (
                validate_cache_for_precommit_phase2_measurement
                    .cpu_time
                    .as_millis() as u64,
                validate_cache_for_precommit_phase2_measurement
                    .wall_time
                    .as_millis() as u64,
            ),
            (
                seal_pre_commit_phase2_measurement.cpu_time.as_millis() as u64,
                seal_pre_commit_phase2_measurement.wall_time.as_millis() as u64,
            ),
        )
    };

    Ok((
        (
            seal_pre_commit_phase1_measurement_cpu_time,
            seal_pre_commit_phase1_measurement_wall_time,
        ),
        (
            validate_cache_for_precommit_phase2_measurement_cpu_time,
            validate_cache_for_precommit_phase2_measurement_wall_time,
        ),
        (
            seal_pre_commit_phase2_measurement_cpu_time,
            seal_pre_commit_phase2_measurement_wall_time,
        ),
    ))
}

pub fn run_window_post_bench<Tree: 'static + MerkleTreeTrait>(
    sector_size: u64,
    cache_dir: PathBuf,
    preserve_cache: bool,
    skip_precommit_phase1: bool,
    skip_precommit_phase2: bool,
    skip_commit_phase1: bool,
    skip_commit_phase2: bool,
) -> anyhow::Result<()> {
    let (
        (seal_pre_commit_phase1_cpu_time_ms, seal_pre_commit_phase1_wall_time_ms),
        (
            validate_cache_for_precommit_phase2_cpu_time_ms,
            validate_cache_for_precommit_phase2_wall_time_ms,
        ),
        (seal_pre_commit_phase2_cpu_time_ms, seal_pre_commit_phase2_wall_time_ms),
    ) = if skip_precommit_phase1 && skip_precommit_phase2 {
        // generate no-op measurements
        Ok(((0, 0), (0, 0), (0, 0)))
    } else {
        run_pre_commit_phases::<Tree>(
            sector_size,
            cache_dir.clone(),
            skip_precommit_phase1,
            skip_precommit_phase2,
        )
    }?;

    let piece_infos = {
        let piece_infos_path = cache_dir.join(PIECE_INFOS_FILE);
        info!("*** Restoring piece infos file");
        let piece_infos_json = read_to_string(&piece_infos_path).with_context(|| {
            format!(
                "could not read file piece_infos_path={:?}",
                piece_infos_path
            )
        })?;

        let res: Vec<PieceInfo> = serde_json::from_str(&piece_infos_json)?;

        res
    };

    let seal_pre_commit_output = {
        let phase2_output_path = cache_dir.join(PRECOMMIT_PHASE2_OUTPUT_FILE);
        info!("*** Restoring precommit phase2 output file");
        let phase2_output_bytes = read(&phase2_output_path).with_context(|| {
            format!(
                "could not read file phase2_output_path={:?}",
                phase2_output_path
            )
        })?;

        let res: SealPreCommitOutput = deserialize(&phase2_output_bytes)?;

        res
    };

    let seed = [0u8; 32];
    let comm_r = seal_pre_commit_output.comm_r;

    let sector_id = SectorId::from(SECTOR_ID);
    let porep_config = get_porep_config(sector_size);

    let sealed_file_path = cache_dir.join(SEALED_FILE);

    let (
        validate_cache_for_commit_cpu_time_ms,
        validate_cache_for_commit_wall_time_ms,
        seal_commit_phase1_cpu_time_ms,
        seal_commit_phase1_wall_time_ms,
    ) = if skip_commit_phase1 {
        // generate no-op measurements
        (0, 0, 0, 0)
    } else {
        let validate_cache_for_commit_measurement = measure(|| {
            validate_cache_for_commit::<_, _, Tree>(cache_dir.clone(), sealed_file_path.clone())
        })
        .expect("failed to validate cache for commit");

        let seal_commit_phase1_measurement = measure(|| {
            seal_commit_phase1::<_, Tree>(
                porep_config,
                cache_dir.clone(),
                sealed_file_path.clone(),
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

        // Persist commit phase1_output here
        let phase1_output_path = cache_dir.join(COMMIT_PHASE1_OUTPUT_FILE);
        let mut f = File::create(&phase1_output_path).with_context(|| {
            format!(
                "could not create file phase1_output_path={:?}",
                phase1_output_path
            )
        })?;
        info!("*** Created commit phase1 output file");
        let phase1_output_bytes = serialize(&phase1_output)?;
        f.write_all(&phase1_output_bytes).with_context(|| {
            format!(
                "could not write to file phase1_output_path={:?}",
                phase1_output_path
            )
        })?;
        info!("Persisted commit phase1 output to {:?}", phase1_output_path);

        (
            validate_cache_for_commit_measurement.cpu_time.as_millis() as u64,
            validate_cache_for_commit_measurement.wall_time.as_millis() as u64,
            seal_commit_phase1_measurement.cpu_time.as_millis() as u64,
            seal_commit_phase1_measurement.wall_time.as_millis() as u64,
        )
    };

    let (seal_commit_phase2_cpu_time_ms, seal_commit_phase2_wall_time_ms) = if skip_commit_phase2 {
        // generate no-op measurements
        (0, 0)
    } else {
        let commit_phase1_output = {
            let commit_phase1_output_path = cache_dir.join(COMMIT_PHASE1_OUTPUT_FILE);
            info!("*** Restoring commit phase1 output file");
            let commit_phase1_output_bytes =
                read(&commit_phase1_output_path).with_context(|| {
                    format!(
                        "could not read file commit_phase1_output_path={:?}",
                        commit_phase1_output_path
                    )
                })?;

            let res: SealCommitPhase1Output<Tree> = deserialize(&commit_phase1_output_bytes)?;

            res
        };

        let seal_commit_phase2_measurement = measure(|| {
            seal_commit_phase2::<Tree>(porep_config, commit_phase1_output, PROVER_ID, sector_id)
        })
        .expect("failed in seal_commit_phase2");

        (
            seal_commit_phase2_measurement.cpu_time.as_millis() as u64,
            seal_commit_phase2_measurement.wall_time.as_millis() as u64,
        )
    };

    let pub_replica = PublicReplicaInfo::new(comm_r).expect("failed to create public replica info");

    let priv_replica = PrivateReplicaInfo::<Tree>::new(sealed_file_path, comm_r, cache_dir.clone())
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
            .expect("WINDOW_POST_SECTOR_COUNT poisoned")
            .get(&sector_size)
            .expect("unknown sector size"),
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

    if preserve_cache {
        info!("Preserving cache directory {:?}", cache_dir);
    } else {
        info!("Removing cache directory {:?}", cache_dir);
        remove_dir_all(cache_dir)?;
    }

    let report = Report {
        inputs: Inputs { sector_size },
        outputs: Outputs {
            seal_pre_commit_phase1_cpu_time_ms,
            seal_pre_commit_phase1_wall_time_ms,
            validate_cache_for_precommit_phase2_cpu_time_ms,
            validate_cache_for_precommit_phase2_wall_time_ms,
            seal_pre_commit_phase2_cpu_time_ms,
            seal_pre_commit_phase2_wall_time_ms,
            validate_cache_for_commit_cpu_time_ms,
            validate_cache_for_commit_wall_time_ms,
            seal_commit_phase1_cpu_time_ms,
            seal_commit_phase1_wall_time_ms,
            seal_commit_phase2_cpu_time_ms,
            seal_commit_phase2_wall_time_ms,
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

pub fn run(
    sector_size: usize,
    cache: String,
    preserve_cache: bool,
    skip_precommit_phase1: bool,
    skip_precommit_phase2: bool,
    skip_commit_phase1: bool,
    skip_commit_phase2: bool,
) -> anyhow::Result<()> {
    info!("Benchy Window PoSt: sector-size={}, preserve_cache={}, skip_precommit_phase1={}, skip_precommit_phase2={}, skip_commit_phase1={}, skip_commit_phase2={}", sector_size, preserve_cache, skip_precommit_phase1, skip_precommit_phase2, skip_commit_phase1, skip_commit_phase2);

    let cache_dir_specified = !cache.is_empty();
    if skip_precommit_phase1 || skip_precommit_phase2 || skip_commit_phase1 || skip_commit_phase2 {
        ensure!(
            !preserve_cache,
            "Preserve cache cannot be used if skipping any stages"
        );
        ensure!(
            cache_dir_specified,
            "Cache dir is required if skipping any stages"
        );
    }

    let (cache_dir, preserve_cache) = if cache_dir_specified {
        // If a cache dir was specified, automatically preserve it.
        (PathBuf::from(cache), true)
    } else {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        (
            std::env::temp_dir().join(format!("window-post-bench-{}", timestamp)),
            preserve_cache,
        )
    };

    if !Path::new(&cache_dir).exists() {
        create_dir(&cache_dir)?;
    }
    info!("Using cache directory {:?}", cache_dir);

    with_shape!(
        sector_size as u64,
        run_window_post_bench,
        sector_size as u64,
        cache_dir,
        preserve_cache,
        skip_precommit_phase1,
        skip_precommit_phase2,
        skip_commit_phase1,
        skip_commit_phase2,
    )
}
