use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::poseidon::PoseidonDomain;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_post::fallback;

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesWindowPoStParameters {
    /// The number of challanges to generate per sector.
    num_challenges_per_sector: usize,
    /// The randomness that determines which challenges are drawn.
    #[serde(with = "SerHex::<StrictPfx>")]
    randomness: [u8; 32],
    /// The list of sector IDs.
    sector_ids: Vec<u64>,
    /// Sector size is used to calculate the number of nodes.
    sector_size: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesWindowPoStOutput {
    challenges: Vec<Vec<u64>>,
}

fn main() -> Result<()> {
    fil_logger::maybe_init();

    let params: ChallengesWindowPoStParameters = cli::parse_stdin()?;
    info!("{:?}", params);

    let randomness_safe: PoseidonDomain =
        filecoin_proofs::as_safe_commitment(&params.randomness, "randomness")?;
    let sector_challenges = params
        .sector_ids
        .into_iter()
        .map(|sector_id| {
            (0..params.num_challenges_per_sector)
                .map(|challenge_index| {
                    fallback::generate_leaf_challenge(
                        params.sector_size,
                        randomness_safe,
                        sector_id,
                        challenge_index as u64,
                    )
                })
                .collect()
        })
        .collect();

    let output = ChallengesWindowPoStOutput {
        challenges: sector_challenges,
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
