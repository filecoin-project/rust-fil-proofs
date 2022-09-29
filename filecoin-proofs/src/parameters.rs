use anyhow::{ensure, Result};
use ff::PrimeField;
use filecoin_hashers::Hasher;
use storage_proofs_core::{api_version::ApiVersion, proof::ProofScheme, util::is_groth16_field};
use storage_proofs_porep::stacked::{self, LayerChallenges, StackedDrg};
use storage_proofs_post::fallback::{self, FallbackPoSt, PoStShape};

use crate::{
    constants::{DefaultPieceHasher, DRG_DEGREE, EXP_DEGREE, LAYERS, POREP_MINIMUM_CHALLENGES},
    types::{MerkleTreeTrait, PaddedBytesAmount, PoStConfig, SectorUpdateConfig},
};

type WinningPostSetupParams = fallback::SetupParams;
pub type WinningPostPublicParams = fallback::PublicParams;

type WindowPostSetupParams = fallback::SetupParams;
pub type WindowPostPublicParams = fallback::PublicParams;

pub fn public_params<Tree: 'static + MerkleTreeTrait>(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
    api_version: ApiVersion,
) -> Result<stacked::PublicParams<Tree>>
where
    DefaultPieceHasher<Tree::Field>: Hasher<Field = Tree::Field>,
{
    StackedDrg::<Tree, DefaultPieceHasher<Tree::Field>>::setup(&setup_params::<Tree::Field>(
        sector_bytes,
        partitions,
        porep_id,
        api_version,
    )?)
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
        post_config.challenge_count,
    );

    Ok(fallback::SetupParams {
        sector_size: post_config.padded_sector_size().into(),
        challenge_count: param_challenge_count,
        sector_count: param_sector_count,
        api_version: post_config.api_version,
        shape: PoStShape::Winning,
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
        shape: PoStShape::Window,
    }
}

pub fn setup_params<F: PrimeField>(
    sector_bytes: PaddedBytesAmount,
    partitions: usize,
    porep_id: [u8; 32],
    api_version: ApiVersion,
) -> Result<stacked::SetupParams> {
    let sector_bytes = u64::from(sector_bytes);

    ensure!(
        sector_bytes % 32 == 0,
        "sector_bytes ({}) must be a multiple of 32",
        sector_bytes,
    );

    let nodes = (sector_bytes / 32) as usize;
    let degree = DRG_DEGREE;
    let expansion_degree = EXP_DEGREE;

    let num_layers = *LAYERS
        .read()
        .expect("LAYERS poisoned")
        .get(&sector_bytes)
        .expect("unknown sector size");

    let layer_challenges = if is_groth16_field::<F>() {
        select_challenges(
            partitions,
            *POREP_MINIMUM_CHALLENGES
                .read()
                .expect("POREP_MINIMUM_CHALLENGES poisoned")
                .get(&sector_bytes)
                .expect("unknown sector size") as usize,
            num_layers,
        )
    } else {
        ensure!(
            partitions == stacked::halo2::partition_count(nodes),
            "unexpected number of halo2 partitions",
        );
        ensure!(
            num_layers == stacked::halo2::num_layers(nodes),
            "unexpected number of layers",
        );
        let challenge_count = stacked::halo2::challenge_count(nodes);
        LayerChallenges::new(num_layers, challenge_count)
    };

    Ok(stacked::SetupParams {
        nodes,
        degree,
        expansion_degree,
        porep_id,
        layer_challenges,
        api_version,
    })
}

fn select_challenges(
    partitions: usize,
    minimum_total_challenges: usize,
    layers: usize,
) -> LayerChallenges {
    let mut count = 1;
    let mut guess = LayerChallenges::new(layers, count);
    while partitions * guess.challenges_count_all() < minimum_total_challenges {
        count += 1;
        guess = LayerChallenges::new(layers, count);
    }

    guess
}

#[inline]
pub fn sector_update_public_params<F: PrimeField>(
    config: &SectorUpdateConfig,
) -> Result<storage_proofs_update::PublicParams> {
    let sector_bytes = u64::from(config.sector_size);
    let pub_params = if is_groth16_field::<F>() {
        storage_proofs_update::PublicParams::from_sector_size(sector_bytes)
    } else {
        storage_proofs_update::PublicParams::from_sector_size_halo2(sector_bytes)
    };
    ensure!(
        pub_params.partition_count == usize::from(config.update_partitions),
        "SectorUpdateConfig contains invalid number of partition",
    );
    Ok(pub_params)
}

#[cfg(test)]
mod tests {
    use super::*;

    use blstrs::Scalar as Fr;

    use crate::{DefaultOctLCTree, PoRepProofPartitions, PoStType};

    #[test]
    fn partition_layer_challenges_test() {
        let f = |partitions| select_challenges(partitions, 12, 11).challenges_count_all();
        // Update to ensure all supported PoRepProofPartitions options are represented here.
        assert_eq!(6, f(usize::from(PoRepProofPartitions(2))));

        assert_eq!(12, f(1));
        assert_eq!(6, f(2));
        assert_eq!(3, f(4));
    }

    #[test]
    fn test_winning_post_params() {
        let config = PoStConfig {
            typ: PoStType::Winning,
            priority: false,
            challenge_count: 66,
            sector_count: 1,
            sector_size: 2048u64.into(),
            api_version: ApiVersion::V1_0_0,
        };

        let params = winning_post_public_params::<DefaultOctLCTree<Fr>>(&config)
            .expect("failed to get params");
        assert_eq!(params.sector_count, 66);
        assert_eq!(params.challenge_count, 1);
        assert_eq!(params.sector_size, 2048);
    }
}
