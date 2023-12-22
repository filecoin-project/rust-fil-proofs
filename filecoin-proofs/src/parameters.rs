use anyhow::{ensure, Result};
use storage_proofs_core::{api_version::ApiFeature, proof::ProofScheme, util};
use storage_proofs_porep::stacked::{self, Challenges, StackedDrg};
use storage_proofs_post::fallback::{self, FallbackPoSt};

use crate::{
    constants::{DefaultPieceHasher, DRG_DEGREE, EXP_DEGREE, LAYERS, MAX_CHALLENGES_PER_PARTITION},
    types::{MerkleTreeTrait, PoRepConfig, PoStConfig},
};

type WinningPostSetupParams = fallback::SetupParams;
pub type WinningPostPublicParams = fallback::PublicParams;

type WindowPostSetupParams = fallback::SetupParams;
pub type WindowPostPublicParams = fallback::PublicParams;

pub fn public_params<Tree: 'static + MerkleTreeTrait>(
    porep_config: &PoRepConfig,
) -> Result<stacked::PublicParams<Tree>> {
    StackedDrg::<Tree, DefaultPieceHasher>::setup(&setup_params(porep_config)?)
}

pub fn winning_post_public_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<WinningPostPublicParams> {
    FallbackPoSt::<Tree>::setup(&winning_post_setup_params(post_config)?)
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
        api_version: post_config.api_version,
    })
}

pub fn window_post_public_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<WindowPostPublicParams> {
    FallbackPoSt::<Tree>::setup(&window_post_setup_params(post_config))
}

pub fn window_post_setup_params(post_config: &PoStConfig) -> WindowPostSetupParams {
    fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: post_config.challenge_count,
        sector_count: post_config.sector_count,
        api_version: post_config.api_version,
    }
}

pub fn setup_params(porep_config: &PoRepConfig) -> Result<stacked::SetupParams> {
    let sector_bytes = porep_config.padded_bytes_amount();
    let challenges = select_challenges(
        usize::from(porep_config.partitions),
        porep_config.minimum_challenges(),
        &porep_config.api_features,
    );
    let num_layers = *LAYERS
        .read()
        .expect("LAYERS poisoned")
        .get(&u64::from(sector_bytes))
        .expect("unknown sector size");
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
        porep_id: porep_config.porep_id,
        challenges,
        num_layers,
        api_version: porep_config.api_version,
        api_features: porep_config.api_features.clone(),
    })
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    features: &[ApiFeature],
) -> Challenges {
    let challenges = util::div_ceil(minimum_total_challenges, partitions);
    assert!(challenges <= usize::from(MAX_CHALLENGES_PER_PARTITION));

    if features.contains(&ApiFeature::SyntheticPoRep) {
        Challenges::new_synthetic(challenges)
    } else if features.contains(&ApiFeature::NonInteractivePoRep) {
        Challenges::new_non_interactive(challenges)
    } else {
        Challenges::new_interactive(challenges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{DefaultOctLCTree, PoRepProofPartitions, PoStType};

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| select_challenges(partitions, 12, &[]).num_challenges_per_partition();
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }

    #[test]
    fn test_winning_post_params() {
        use storage_proofs_core::api_version::ApiVersion;

        let config = PoStConfig {
            typ: PoStType::Winning,
            priority: false,
            challenge_count: 66,
            sector_count: 1,
            sector_size: 2048u64.into(),
            api_version: ApiVersion::V1_2_0,
        };

        let params =
            winning_post_public_params::<DefaultOctLCTree>(&config).expect("failed to get params");
        assert_eq!(params.sector_count, 66);
        assert_eq!(params.challenge_count, 1);
        assert_eq!(params.sector_size, 2048);
    }
}
