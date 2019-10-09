use std::collections::BTreeMap;
use std::io::stdout;

use fil_proofs_tooling::{measure, Metadata};
use filecoin_proofs::fr32::write_padded;
use filecoin_proofs::pieces::get_aligned_source;
use filecoin_proofs::types::{
    PaddedBytesAmount, PoRepConfig, PoRepProofPartitions, PoStConfig, SectorSize,
    UnpaddedBytesAmount,
};
use filecoin_proofs::{generate_post, seal, verify_post, PrivateReplicaInfo, PublicReplicaInfo};
use log::info;
use rand::random;
use storage_proofs::sector::SectorId;
use tempfile::NamedTempFile;

// The seed for the rng used to generate which sectors to challenge.
const CHALLENGE_SEED: [u8; 32] = [0; 32];

const PROVER_ID: [u8; 31] = [0; 31];
const SECTOR_ID: u64 = 0;
const N_PARTITIONS: PoRepProofPartitions = PoRepProofPartitions(1);

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Inputs {
    sector_size: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Outputs {
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

pub fn run(sector_size: usize) -> Result<(), failure::Error> {
    info!("Benchy Rational PoSt: sector-size={}", sector_size);

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
    let data: Vec<u8> = (0..sector_size).map(|_| random()).collect();

    // Write the aligned data to the staged sector file.
    let (_, mut aligned_data) =
        get_aligned_source(&data[..], &[], sector_size_unpadded_bytes_ammount);

    write_padded(&mut aligned_data, &mut staged_file)
        .expect("failed to write padded data to staged sector file");

    // Replicate the staged sector, write the replica file to `sealed_path`.
    let porep_config = PoRepConfig(SectorSize(sector_size as u64), N_PARTITIONS);
    let sector_id = SectorId::from(SECTOR_ID);
    let ticket = [0u8; 32];

    let seal_output = seal(
        porep_config,
        staged_file.path(),
        sealed_file.path(),
        &PROVER_ID,
        sector_id,
        ticket,
        &[sector_size_unpadded_bytes_ammount],
    )
    .expect("failed to seal");

    // Store the replica's private and publicly facing info for proving and verifying respectively.
    let mut pub_replica_info: BTreeMap<SectorId, PublicReplicaInfo> = BTreeMap::new();
    let mut priv_replica_info: BTreeMap<SectorId, PrivateReplicaInfo> = BTreeMap::new();

    pub_replica_info.insert(sector_id, PublicReplicaInfo::new(seal_output.comm_r));

    priv_replica_info.insert(
        sector_id,
        PrivateReplicaInfo::new(sealed_path_string, seal_output.comm_r, seal_output.p_aux),
    );

    // Measure PoSt generation and verification.
    let post_config = PoStConfig(SectorSize(sector_size as u64));

    let gen_post_measurement =
        measure(|| generate_post(post_config, &CHALLENGE_SEED, &priv_replica_info))
            .expect("failed to generate PoSt");

    let proof = &gen_post_measurement.return_value;

    let verify_post_measurement =
        measure(|| verify_post(post_config, &CHALLENGE_SEED, proof, &pub_replica_info))
            .expect("failed to verify PoSt");

    // Create a JSON serializable report that we print to stdout (that will later be parsed using
    // the CLI JSON parser `jq`).
    let report = Report {
        inputs: Inputs { sector_size },
        outputs: Outputs {
            proving_cpu_time_ms: gen_post_measurement.cpu_time.as_millis() as u64,
            proving_wall_time_ms: gen_post_measurement.wall_time.as_millis() as u64,
            verifying_cpu_time_ms: verify_post_measurement.cpu_time.as_millis() as u64,
            verifying_wall_time_ms: verify_post_measurement.wall_time.as_millis() as u64,
        },
    };

    report.print();
    Ok(())
}
