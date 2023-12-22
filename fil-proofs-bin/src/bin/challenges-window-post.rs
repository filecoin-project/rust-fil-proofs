use anyhow::Result;
use fil_proofs_bin::cli;
use filecoin_hashers::poseidon::PoseidonDomain;
use log::info;
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictPfx};
use storage_proofs_post::fallback;

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesWindowPoStParameters {
    /// The directory where the tree files are stored.
    cache_dir: String,
    #[serde(with = "SerHex::<StrictPfx>")]
    comm_r: [u8; 32],
    /// The number of challanges to generate per sector.
    num_challenges_per_sector: usize,
    /// The randomness that determines which challenges are drawn.
    #[serde(with = "SerHex::<StrictPfx>")]
    randomness: [u8; 32],
    /// A list of paths to replica files.
    replica_paths: Vec<String>,
    /// The list of sector IDs. Need to match the replica paths.
    sector_ids: Vec<u64>,
    /// Sector size is used to calculate the number of nodes.
    sector_size: u64,
}

///home/vmx/src/pl/filecoin/rust-fil-proofs/filecoin-proofs/tests/api.rs:1675: fn window_post

#[derive(Debug, Deserialize, Serialize)]
struct ChallengesWindowPoStOutput {
    challenges: Vec<Vec<u64>>,
}


fn main() -> Result<()> {
    let params: ChallengesWindowPoStParameters = cli::parse_stdin()?;
    fil_logger::maybe_init();

    info!("{:?}", params);

    let sector_count = params.sector_ids.len();
    let randomness_safe: PoseidonDomain = filecoin_proofs::as_safe_commitment(&params.randomness, "randomness")?;

    //let mut sector_challenges: BTreeMap<u64, Vec<u64>> = BTreeMap::new();

    // TODO vmx 2023-12-22: It looks like th number of sectors per chunk is always equal to the
    // number of sectors. Check all code paths if that's really the case as maybe things could be
    // simplified then. It would mean that there's always only a single partition.
    //let num_sectors_per_chunk = sector_count;
    //let partitions = util::div_ceil(sector_ids.len(), num_sectors_per_chunk);
    //for partition_index in 0..partitions {
    //    let sectors = sector_ids
    //        .chunks(num_sectors_per_chunk)
    //        .nth(partition_index)
    //        .ok_or_else(|| anyhow!("invalid number of sectors/partition index"))?;
    //
    //    for (i, sector) in sectors.iter().enumerate() {
    //        let mut challenges = Vec::new();
    //
    //        // Defining `challenge_index` this way is only a valid for >= ApiVersion::V1_2_0.
    //        for challenge_index in 0..post_config.challenge_count {
    //            let sector_index =  partition_index * num_sectors_per_chunk + i;
    //            let challenged_leaf = generate_leaf_challenge(
    //                sector_size,
    //                randomness_safe,
    //                u64::from(*sector),
    //                challenge_index,
    //            );
    //            challenges.push(challenged_leaf);
    //        }
    //
    //        sector_challenges.insert(*sector, challenges);
    //    }
    //}

GO ON HERE 2023-12-22: and check if this actually does the right thing.

    let mut sector_challenges = Vec::with_capacity(sector_count);

    for sector_id in params.sector_ids {
        let mut challenges = Vec::new();

        // Defining `challenge_index` this way is only a valid for >= ApiVersion::V1_2_0.
        for challenge_index in 0..params.num_challenges_per_sector {
            let challenged_leaf = fallback::generate_leaf_challenge(
                params.sector_size,
                randomness_safe,
                sector_id,
                challenge_index as u64,
            );
            challenges.push(challenged_leaf);
        }
        sector_challenges.push(challenges);
    }

    let output = ChallengesWindowPoStOutput {
        challenges: sector_challenges,
    };
    info!("{:?}", output);
    cli::print_stdout(output)?;

    Ok(())
}
