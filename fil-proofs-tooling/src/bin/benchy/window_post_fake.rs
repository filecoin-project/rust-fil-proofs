use std::collections::BTreeMap;
use std::fs::{remove_dir_all, remove_file};
use std::io::stdout;

use blstrs::Scalar as Fr;
use fil_proofs_tooling::shared::{create_replica, PROVER_ID, RANDOMNESS};
use fil_proofs_tooling::{measure, Metadata};
use filecoin_hashers::{Domain, Hasher};
use filecoin_proofs::constants::{WINDOW_POST_CHALLENGE_COUNT, WINDOW_POST_SECTOR_COUNT};
use filecoin_proofs::types::{PoStConfig, SectorSize};
use filecoin_proofs::{
    generate_window_post, verify_window_post, with_shape, PoStType, PrivateReplicaInfo,
    PublicReplicaInfo,
};
use log::info;
use serde::Serialize;
use storage_proofs_core::{api_version::ApiVersion, merkle::MerkleTreeTrait, sector::SectorId};

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Inputs {
    sector_size: u64,
    fake_replica: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Outputs {
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

pub fn run_window_post_bench<Tree>(
    sector_size: u64,
    fake_replica: bool,
    api_version: ApiVersion,
) -> anyhow::Result<()>
where
    Tree: 'static + MerkleTreeTrait,
    <Tree::Hasher as Hasher>::Domain: Domain<Field = Fr>,
{
    let arbitrary_porep_id = [66; 32];
    let sector_count = *WINDOW_POST_SECTOR_COUNT
        .read()
        .expect("WINDOW_POST_SECTOR_COUNT poisoned")
        .get(&sector_size)
        .expect("unknown sector size");

    let (sector_id, replica_output) =
        create_replica::<Tree>(sector_size, arbitrary_porep_id, fake_replica, api_version);

    // Store the replica's private and publicly facing info for proving and verifying respectively.
    let mut pub_replica_info: BTreeMap<SectorId, PublicReplicaInfo> = BTreeMap::new();
    let mut priv_replica_info: BTreeMap<SectorId, PrivateReplicaInfo<Tree>> = BTreeMap::new();

    pub_replica_info.insert(sector_id, replica_output.public_replica_info.clone());
    priv_replica_info.insert(sector_id, replica_output.private_replica_info.clone());

    // Measure PoSt generation and verification.
    let post_config = PoStConfig {
        sector_size: SectorSize(sector_size),
        challenge_count: WINDOW_POST_CHALLENGE_COUNT,
        sector_count,
        typ: PoStType::Window,
        priority: false,
        api_version,
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
            proof,
        )
    })
    .expect("failed to verify window post proof");

    // Clean-up sealed file.
    remove_file(&replica_output.private_replica_info.replica_path())?;
    remove_dir_all(&replica_output.private_replica_info.cache_dir_path())?;

    // Create a JSON serializable report that we print to stdout (that will later be parsed using
    // the CLI JSON parser `jq`).
    let report = Report {
        inputs: Inputs {
            sector_size,
            fake_replica,
        },
        outputs: Outputs {
            gen_window_post_cpu_time_ms: gen_window_post_measurement.cpu_time.as_millis() as u64,
            gen_window_post_wall_time_ms: gen_window_post_measurement.wall_time.as_millis() as u64,
            verify_window_post_cpu_time_ms: verify_window_post_measurement.cpu_time.as_millis()
                as u64,
            verify_window_post_wall_time_ms: verify_window_post_measurement.wall_time.as_millis()
                as u64,
        },
    };
    report.print();
    Ok(())
}

pub fn run(sector_size: usize, fake_replica: bool, api_version: ApiVersion) -> anyhow::Result<()> {
    info!(
        "Benchy Window PoSt Fake: sector-size={}, fake_replica={}, api_version={}",
        sector_size, fake_replica, api_version
    );

    with_shape!(
        sector_size as u64,
        run_window_post_bench,
        sector_size as u64,
        fake_replica,
        api_version,
    )
}
