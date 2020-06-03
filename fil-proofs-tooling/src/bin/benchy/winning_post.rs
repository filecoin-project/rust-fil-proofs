use std::io::stdout;

use anyhow::anyhow;
use fil_proofs_tooling::shared::{create_replica, PROVER_ID, RANDOMNESS};
use fil_proofs_tooling::{measure, Metadata};
use filecoin_proofs::constants::{WINNING_POST_CHALLENGE_COUNT, WINNING_POST_SECTOR_COUNT};
use filecoin_proofs::types::PoStConfig;
use filecoin_proofs::{
    generate_winning_post, generate_winning_post_sector_challenge, verify_winning_post, with_shape,
    PoStType,
};
use log::info;
use serde::Serialize;
use storage_proofs::merkle::MerkleTreeTrait;

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
    if WINNING_POST_SECTOR_COUNT != 1 {
        return Err(anyhow!(
            "This benchmark only works with WINNING_POST_SECTOR_COUNT == 1"
        ));
    }
    let arbitrary_porep_id = [66; 32];
    let (sector_id, replica_output) = create_replica::<Tree>(sector_size, arbitrary_porep_id);

    // Store the replica's private and publicly facing info for proving and verifying respectively.
    let pub_replica_info = vec![(sector_id, replica_output.public_replica_info)];
    let priv_replica_info = vec![(sector_id, replica_output.private_replica_info)];

    let post_config = PoStConfig {
        sector_size: sector_size.into(),
        sector_count: WINNING_POST_SECTOR_COUNT,
        challenge_count: WINNING_POST_CHALLENGE_COUNT,
        typ: PoStType::Winning,
        priority: true,
    };

    let gen_winning_post_sector_challenge_measurement = measure(|| {
        generate_winning_post_sector_challenge::<Tree>(
            &post_config,
            &RANDOMNESS,
            WINNING_POST_SECTOR_COUNT as u64,
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
    info!("Benchy Winning PoSt: sector-size={}", sector_size,);

    with_shape!(
        sector_size as u64,
        run_fallback_post_bench,
        sector_size as u64
    )
}
