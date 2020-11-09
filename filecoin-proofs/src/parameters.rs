use anyhow::{ensure, Result};
use storage_proofs::porep::stacked::{self, LayerChallenges, StackedDrg};
use storage_proofs::post::fallback;
use storage_proofs::proof::ProofScheme;

use crate::constants::*;
use crate::types::{MerkleTreeTrait, PaddedBytesAmount, PoStConfig};

type WinningPostSetupParams = fallback::SetupParams;
pub type WinningPostPublicParams = fallback::PublicParams;

type WindowPostSetupParams = fallback::SetupParams;
pub type WindowPostPublicParams = fallback::PublicParams;

pub fn public_params<Tree: 'static + MerkleTreeTrait>(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
) -> Result<stacked::PublicParams<Tree>> {
    StackedDrg::<Tree, DefaultPieceHasher>::setup(&setup_params(
        sector_bytes,
        partitions,
        porep_id,
    )?)
}

pub fn winning_post_public_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<WinningPostPublicParams> {
    fallback::FallbackPoSt::<Tree>::setup(&winning_post_setup_params(&post_config)?)
}

pub fn winning_post_setup_params(post_config: &PoStConfig) -> Result<WinningPostSetupParams> {
    ensure!(
        post_config.challenge_count % post_config.sector_count == 0,
        "sector count must divide challenge count"
    );

    let param_sector_count = post_config.challenge_count / post_config.sector_count;
    let param_challenge_count = post_config.challenge_count / param_sector_count;

    ensure!(
        param_sector_count * param_challenge_count == post_config.challenge_count,
        "invald parameters calculated {} * {} != {}",
        param_sector_count,
        param_challenge_count,
        post_config.challenge_count
    );

    Ok(fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: param_challenge_count,
        sector_count: param_sector_count,
    })
}

pub fn window_post_public_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<WindowPostPublicParams> {
    fallback::FallbackPoSt::<Tree>::setup(&window_post_setup_params(&post_config))
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
    porep_id: [u8; 32],
) -> Result<stacked::SetupParams> {
    let layer_challenges = select_challenges(
        partitions,
        *POREP_MINIMUM_CHALLENGES
            .read()
            .expect("POREP_MINIMUM_CHALLENGES poisoned")
            .get(&u64::from(sector_bytes))
            .expect("unknown sector size") as usize,
        *LAYERS
            .read()
            .expect("LAYERS poisoned")
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
        porep_id,
        layer_challenges,
    })
}

pub fn select_challenges(
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
