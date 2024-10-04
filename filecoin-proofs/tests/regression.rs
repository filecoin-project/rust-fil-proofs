use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use anyhow::Result;
use filecoin_proofs::{
    verify_seal, SealRegressionRecord, SectorShape16KiB, SectorShape1GiB, SectorShape2KiB,
    SectorShape32GiB, SectorShape32KiB, SectorShape4KiB, SectorShape512MiB, SectorShape64GiB,
    SectorShape8MiB, SECTOR_SIZE_16_KIB, SECTOR_SIZE_1_GIB, SECTOR_SIZE_2_KIB, SECTOR_SIZE_32_GIB,
    SECTOR_SIZE_32_KIB, SECTOR_SIZE_4_KIB, SECTOR_SIZE_512_MIB, SECTOR_SIZE_64_GIB,
    SECTOR_SIZE_8_MIB,
};
use log::{error, info};

#[cfg(feature = "persist-regression-proofs")]
use filecoin_proofs::{
    MerkleTreeTrait, PoRepConfig, ProverId, SealCommitOutput, SealPreCommitOutput,
    PUBLISHED_SECTOR_SIZES,
};
#[cfg(feature = "persist-regression-proofs")]
use storage_proofs_core::sector::SectorId;

const V16_SEAL_REGRESSION_RECORDS: &str = "seal_regression_records-v16.json";
const V18_SEAL_REGRESSION_RECORDS: &str = "seal_regression_records-v18.json";

#[cfg(feature = "persist-regression-proofs")]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_generated_proof_for_regression_testing<Tree: 'static + MerkleTreeTrait>(
    config: &PoRepConfig,
    prover_id: ProverId,
    sector_id: SectorId,
    ticket: [u8; 32],
    seed: [u8; 32],
    pre_commit_output: &SealPreCommitOutput,
    commit_output: &SealCommitOutput,
) -> Result<()> {
    use std::io::Write;

    use anyhow::ensure;
    use file_lock::{FileLock, FileOptions};

    const DEFAULT_SEAL_REGRESSION_RECORD: &str = "seal_regression_records.json";

    // First, make sure that we're only persisting sector sizes with
    // published parameters so that everyone can verify them properly
    let sector_size: u64 = config.sector_size.into();

    if PUBLISHED_SECTOR_SIZES.contains(&sector_size) {
        // When generating a new record file, use a default path for persisting them
        let output_path = Path::new(&std::env::var("CARGO_MANIFEST_DIR")?)
            .join("tests")
            .join(DEFAULT_SEAL_REGRESSION_RECORD);

        let comm_d = pre_commit_output.comm_d;
        let comm_r = pre_commit_output.comm_r;

        // Then verify this proof before persisting it
        let verified = verify_seal::<Tree>(
            config,
            comm_r,
            comm_d,
            prover_id,
            sector_id,
            ticket,
            seed,
            &commit_output.proof,
        )?;
        ensure!(verified, "failed to verify valid seal");

        let record = SealRegressionRecord {
            porep_config: config.clone(),
            comm_r,
            comm_d,
            prover_id,
            sector_id,
            ticket,
            seed,
            proof: commit_output.proof.clone(),
        };

        let json = serde_json::to_string(&record)?;

        // When appending to an existing file, the file lock is required
        // to avoid corruption when multiple tests running in parallel are
        // persisting generated proofs
        let options = FileOptions::new().write(true).create(true).append(true);
        let mut filelock = FileLock::lock(output_path, true /* block */, options)?;
        writeln!(filelock.file, "{}", json)?;
    }

    Ok(())
}

pub(crate) fn load_regression_records(records: &Path) -> Result<Vec<SealRegressionRecord>> {
    // Note that when reading regression records, it's assumed that
    // the specified record file is not also being written in parallel
    let file = File::open(records)?;
    let inputs = io::BufReader::new(file).lines();

    let mut records = Vec::new();
    for input in inputs {
        let input = input.unwrap();
        let record: SealRegressionRecord = serde_json::from_str(&input)?;
        records.push(record);
    }

    Ok(records)
}

// On MacOS, we only verify production parameter sizes and published test sector sizes
#[cfg(target_os = "macos")]
pub(crate) fn regression_verify_seal_proof(record: &SealRegressionRecord) -> Result<bool> {
    let r = record;

    let sector_size: u64 = r.porep_config.sector_size.into();
    let verified = match sector_size {
        SECTOR_SIZE_2_KIB => verify_seal::<SectorShape2KiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_4_KIB | SECTOR_SIZE_16_KIB | SECTOR_SIZE_32_KIB => true,
        SECTOR_SIZE_8_MIB => verify_seal::<SectorShape8MiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_512_MIB => verify_seal::<SectorShape512MiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_1_GIB => true,
        SECTOR_SIZE_32_GIB => verify_seal::<SectorShape32GiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_64_GIB => verify_seal::<SectorShape64GiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        _ => {
            error!(
                "Cannot verify proof: Unsupported sector size [{}]",
                sector_size
            );
            Ok(false)
        }
    }?;

    Ok(verified)
}

#[allow(non_snake_case)]
#[allow(unused_variables)]
#[cfg(not(target_os = "macos"))]
pub(crate) fn regression_verify_seal_proof(record: &SealRegressionRecord) -> Result<bool> {
    let r = record;

    let sector_size: u64 = r.porep_config.sector_size.into();
    let verified = match sector_size {
        SECTOR_SIZE_2_KIB => verify_seal::<SectorShape2KiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_4_KIB => verify_seal::<SectorShape4KiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_16_KIB => verify_seal::<SectorShape16KiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_32_KIB => verify_seal::<SectorShape32KiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_8_MIB => verify_seal::<SectorShape8MiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_512_MIB => verify_seal::<SectorShape512MiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_1_GIB => verify_seal::<SectorShape1GiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_32_GIB => verify_seal::<SectorShape32GiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        SECTOR_SIZE_64_GIB => verify_seal::<SectorShape64GiB>(
            &r.porep_config,
            r.comm_r,
            r.comm_d,
            r.prover_id,
            r.sector_id,
            r.ticket,
            r.seed,
            &r.proof,
        ),
        _ => {
            error!(
                "Cannot verify proof: Unsupported sector size [{}]",
                sector_size
            );
            Ok(false)
        }
    }?;

    Ok(verified)
}

#[test]
fn run_seal_regression_tests() -> Result<()> {
    fil_logger::maybe_init();

    let basedir = Path::new(&std::env::var("CARGO_MANIFEST_DIR")?).join("tests");
    let seal_regression_record_versions = vec![
        (V16_SEAL_REGRESSION_RECORDS, "v16"),
        (V18_SEAL_REGRESSION_RECORDS, "v18"),
    ];

    for (path, version) in seal_regression_record_versions {
        let path = basedir.join(path);
        info!("Loading regression records from {:?}", path);
        let records = load_regression_records(&path)?;
        let total_records = records.len();
        for (i, record) in records.iter().enumerate() {
            let sector_size: u64 = record.porep_config.sector_size.into();
            let status = match regression_verify_seal_proof(record)? {
                true => "OK",
                false => "FAILED",
            };
            info!(
                "[Record {}/{}: {}] seal regression record verified for sector size {}: [{}]",
                i, total_records, version, sector_size, status
            );
        }
        info!("Done processing regression records from {:?}", path);
    }

    Ok(())
}
