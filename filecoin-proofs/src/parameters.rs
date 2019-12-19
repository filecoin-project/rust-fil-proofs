use std::sync::atomic::Ordering;

use anyhow::{anyhow, ensure, Result};
use storage_proofs::drgraph::DefaultTreeHasher;
use storage_proofs::election_post::{self, ElectionPoSt};
use storage_proofs::proof::ProofScheme;
use storage_proofs::stacked_old::{self, LayerChallenges, StackedDrg};

use crate::constants::{
    DefaultPieceHasher, LAYERS, POREP_WINDOW_MINIMUM_CHALLENGES, WINDOW_DRG_DEGREE,
    WINDOW_EXP_DEGREE,
};
use crate::types::{PaddedBytesAmount, PoStConfig};

const DRG_SEED: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27,
]; // Arbitrary, need a theory for how to vary this over time.

type PostSetupParams = election_post::SetupParams;
pub type PostPublicParams = election_post::PublicParams;

pub fn public_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> Result<stacked_old::PublicParams<DefaultTreeHasher>> {
    StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::setup(&setup_params(
        sector_bytes,
        partitions,
    )?)
}

pub fn window_size_nodes_for_sector_bytes(sector_size: PaddedBytesAmount) -> Result<u64> {
    use crate::constants::DEFAULT_WINDOWS;
    match DEFAULT_WINDOWS.read().unwrap().get(&u64::from(sector_size)) {
        Some(info) => Ok(info.window_size_nodes()),
        None => Err(anyhow!("Unknown sector size {:?}", sector_size)),
    }
}

pub fn post_public_params(post_config: PoStConfig) -> Result<PostPublicParams> {
    ElectionPoSt::<DefaultTreeHasher>::setup(&post_setup_params(post_config))
}

pub fn post_setup_params(post_config: PoStConfig) -> PostSetupParams {
    let size = PaddedBytesAmount::from(post_config);

    election_post::SetupParams {
        sector_size: size.into(),
        challenge_count: crate::constants::POST_CHALLENGE_COUNT,
        challenged_nodes: crate::constants::POST_CHALLENGED_NODES,
    }
}

pub fn setup_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> Result<stacked_old::SetupParams> {
    let layer_challenges = select_challenges(
        partitions,
        POREP_WINDOW_MINIMUM_CHALLENGES.load(Ordering::Relaxed) as usize,
        LAYERS.load(Ordering::Relaxed) as usize,
    )?;
    let window_size_nodes = window_size_nodes_for_sector_bytes(sector_bytes)?;
    let sector_bytes = u64::from(sector_bytes);

    ensure!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );

    ensure!(
        sector_bytes % window_size_nodes * 32 == 0,
        "sector_bytes ({}) must be a multiple of the window size ({})",
        sector_bytes,
        window_size_nodes * 32
    );

    let nodes = (sector_bytes / 32) as usize;
    Ok(stacked_old::SetupParams {
        nodes,
        degree: WINDOW_DRG_DEGREE.load(Ordering::Relaxed) as usize,
        expansion_degree: WINDOW_EXP_DEGREE.load(Ordering::Relaxed) as usize,
        seed: DRG_SEED,
        layer_challenges,
    })
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    layers: usize,
) -> Result<LayerChallenges> {
    let mut count = 1;
    let mut guess = LayerChallenges::new(layers, count);
    while partitions * guess.challenges_count_all() < minimum_total_challenges {
        count += 1;
        guess = LayerChallenges::new(layers, count);
    }
    Ok(guess)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| {
            select_challenges(partitions, 12, LAYERS.load(Ordering::Relaxed) as usize)
                .unwrap()
                .challenges_count_all()
        };
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(crate::PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }
}
