use anyhow::{ensure, Result};
use storage_proofs::porep::stacked::{self, LayerChallenges, StackedDrg};
use storage_proofs::post::election::{self, ElectionPoSt};
use storage_proofs::post::fallback;
use storage_proofs::proof::ProofScheme;

use crate::constants::{
    DefaultPieceHasher, DefaultTreeHasher, DRG_DEGREE, EXP_DEGREE, LAYERS, POREP_MINIMUM_CHALLENGES,
};
use crate::types::{PaddedBytesAmount, PoStConfig};

const DRG_SEED: [u8; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27,
]; // Arbitrary, need a theory for how to vary this over time.

type ElectionPostSetupParams = election::SetupParams;
pub type ElectionPostPublicParams = election::PublicParams;

type WinningPostSetupParams = fallback::SetupParams;
pub type WinningPostPublicParams = fallback::PublicParams;

type WindowPostSetupParams = fallback::SetupParams;
pub type WindowPostPublicParams = fallback::PublicParams;

pub fn public_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> Result<stacked::PublicParams<DefaultTreeHasher>> {
    StackedDrg::<DefaultTreeHasher, DefaultPieceHasher>::setup(&setup_params(
        sector_bytes,
        partitions,
    )?)
}

pub fn election_post_public_params(post_config: &PoStConfig) -> Result<ElectionPostPublicParams> {
    ElectionPoSt::<DefaultTreeHasher>::setup(&election_post_setup_params(&post_config))
}

pub fn election_post_setup_params(post_config: &PoStConfig) -> ElectionPostSetupParams {
    election::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: post_config.challenge_count,
        challenged_nodes: 1,
    }
}

pub fn winning_post_public_params(post_config: &PoStConfig) -> Result<WinningPostPublicParams> {
    fallback::FallbackPoSt::<DefaultTreeHasher>::setup(&winning_post_setup_params(&post_config))
}

pub fn winning_post_setup_params(post_config: &PoStConfig) -> WinningPostSetupParams {
    fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: post_config.challenge_count,
        sector_count: post_config.sector_count,
    }
}

pub fn window_post_public_params(post_config: &PoStConfig) -> Result<WindowPostPublicParams> {
    fallback::FallbackPoSt::<DefaultTreeHasher>::setup(&window_post_setup_params(&post_config))
}

pub fn window_post_setup_params(post_config: &PoStConfig) -> WindowPostSetupParams {
    fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: post_config.challenge_count,
        sector_count: post_config.sector_count,
    }
}

pub fn setup_params(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
) -> Result<stacked::SetupParams> {
    let layer_challenges = select_challenges(
        partitions,
        *POREP_MINIMUM_CHALLENGES
            .read()
            .unwrap()
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size") as usize,
        *LAYERS
            .read()
            .unwrap()
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size"),
    )?;
    let sector_bytes = u64::from(sector_bytes);

    ensure!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );

    let nodes = (sector_bytes / 32) as usize;
    let degree = DRG_DEGREE;
    let expansion_degree = EXP_DEGREE;

    Ok(stacked::SetupParams {
        nodes,
        degree,
        expansion_degree,
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
            select_challenges(partitions, 12, 11)
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
